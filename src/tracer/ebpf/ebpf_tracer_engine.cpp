/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "ebpf_tracer_engine.h"
#include "../../logging/easylogging++.h"
#include <iostream>
#include <limits.h>
#include <unordered_map>

#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

std::string debugTraceFile;

double g_bootSecSinceEpoch = 0;
int machineId = 0;

int     g_clkTck = 100;
size_t  g_pwEntrySize = 0;

bool debugTrace = false;
std::vector<Event> events;
std::vector<struct SyscallSchema> schemas = Utils::CollectSyscallSchema();
void* symResolver = NULL;
std::vector<int> pids;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;;

const ebpfSyscallRTPprog        RTPenterProgs[] =
{
    {"genericRawEnter", EBPF_GENERIC_SYSCALL}
};

const ebpfSyscallRTPprog        RTPexitProgs[] =
{
    {"genericRawExit", EBPF_GENERIC_SYSCALL}
};

const ebpfTelemetryMapObject mapObjects[4] =
{
    {"configuration", 0, NULL, NULL},
    {"pids", 0, NULL, NULL},
    {"runstate", 0, NULL, NULL},
    {"syscalls", 0, NULL, NULL}
};

// this holds the FDs for the above maps.
// mapObjects above gets passed into sysinternalsEBPF config during telemetryStart.
// mapFds also gets passed into telemetryStart. mapFds gets populated during telemetryStart
// and can subsequently be used to access the maps.
int mapFds[sizeof(mapObjects) / sizeof(*mapObjects)];

//--------------------------------------------------------------------
//
// logHandler
//
// Handles logs from sysinternalsEBPF
//
//--------------------------------------------------------------------
void logHandler(const char *format, va_list args)
{
    va_list args_copy;
    va_copy(args_copy, args);
    int required_size = vsnprintf(nullptr, 0, format, args_copy) + 1;
    va_end(args_copy);

    if(required_size <= 0)
    {
        return;
    }

    // Allocate buffer
    char *buffer = new char[required_size];
    if(buffer == nullptr)
    {
        return;
    }

    // Format the message
    vsnprintf(buffer, required_size, format, args);

    // Log the message using Easylogging++
    LOG(DEBUG) << buffer;

    // Clean up
    delete[] buffer;
    //vfprintf(stderr, format, args);
}

//--------------------------------------------------------------------
//
// telemetryReady
//
// Callback from loader library to indicate that it has started up.
//
//--------------------------------------------------------------------
void telemetryReady()
{
    //
    // Set PID
    //
    pid_t act_pid = getpid();
    int key = CONFIG_PID_KEY;
    telemetryMapUpdateElem(mapFds[CONFIG_INDEX], &key, &act_pid, MAP_UPDATE_CREATE_OR_OVERWRITE);

    //
    // Set runstate
    //
    int state = TRACER_RUNNING;
    key = RUNSTATE_KEY;
    telemetryMapUpdateElem(mapFds[RUNSTATE_INDEX], &key, &state, MAP_UPDATE_CREATE_OR_OVERWRITE);

    //
    // Init the PIDs
    //
    int init_pid = -1;
    for(int i=0; i<MAX_PIDS; i++)
    {
       telemetryMapUpdateElem(mapFds[PIDS_INDEX], &i, &init_pid, MAP_UPDATE_CREATE_OR_OVERWRITE);
    }

    for(int i=0; i<pids.size(); i++)
    {
        telemetryMapUpdateElem(mapFds[PIDS_INDEX], &i, &pids[i], MAP_UPDATE_CREATE_OR_OVERWRITE);
    }

    //
    // Set targeted syscalls
    //
    for (auto event : events)
    {
        auto schemaItr = std::find_if(schemas.begin(), schemas.end(), [event](auto s) -> bool {return event.Name().compare(s.syscallName) == 0; });
        if(schemaItr != schemas.end())
        {
            std::string str = schemaItr->syscallName;
            char* charPtr = new char[str.size() + 1];
            std::strcpy(charPtr, str.c_str());

            int num = ::Utils::GetSyscallNumberForName(event.Name());
            telemetryMapUpdateElem(mapFds[SYSCALL_INDEX], &num, static_cast<void*>(&(*schemaItr)), MAP_UPDATE_CREATE_OR_OVERWRITE);
        }
    }

    //
    // Signal the consuming thread that telemetry has been initialized
    //
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
}

//--------------------------------------------------------------------
//
// configChange
//
// Called when config has changed.
//
//--------------------------------------------------------------------
void configChange()
{
}

//--------------------------------------------------------------------
//
// SetBootTime
//
// Sets the boot time.
//
//--------------------------------------------------------------------
void SetBootTime()
{
    FILE *fp = NULL;
    double uptimeF = 0.0;
    char machineIdStr[9];
    struct timeval tv;

    fp = fopen( "/proc/uptime", "r" );
    if (fp != NULL) {
        if(fscanf(fp, "%lf", &uptimeF) == EOF) {
            fclose(fp);
            return;
        }

        gettimeofday(&tv, NULL);

        g_bootSecSinceEpoch = (double)tv.tv_sec + ((double)tv.tv_usec / (1000 * 1000)) - uptimeF;
        fclose(fp);
    } else {
        g_bootSecSinceEpoch = 0.0;
    }

    g_clkTck = sysconf( _SC_CLK_TCK );
    // if error, set it to the default of 100
    if (g_clkTck <= 0) {
        g_clkTck = 100;
    }

    // get passwd entry size, or guess at 4K if not
    g_pwEntrySize = sysconf( _SC_GETPW_R_SIZE_MAX );
    if (g_pwEntrySize == (size_t)-1) {
        g_pwEntrySize = 4096;
    }

    // get the machineId
    machineId = 0;
    fp = fopen( "/etc/machine-id", "r" );
    if (fp != NULL) {
        if (fread( machineIdStr, 1, 8, fp ) == 8) {
            machineIdStr[8] = 0x00;
            machineId = strtol( machineIdStr, NULL, 16 );
        }
        fclose( fp );
    }
}


//--------------------------------------------------------------------
//
// Initialize
//
// Initializes the eBPF tracer engine.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::Initialize()
{
    PollingThread = std::thread(&EbpfTracerEngine::Poll, this);
    ConsumerThread = std::thread(&EbpfTracerEngine::Consume, this);
}


//--------------------------------------------------------------------
//
// EbpfTracerEngine
//
// Constructor for the eBPF tracer engine.
//
//--------------------------------------------------------------------
EbpfTracerEngine::EbpfTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents, std::vector<int> pidList)
    : ITracerEngine(storageEngine, targetEvents), Schemas(Utils::CollectSyscallSchema())
{
    events = targetEvents;
    pids = pidList;
}

//--------------------------------------------------------------------
//
// SetRunState
//
// Sets the run state of the tracer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::SetRunState(int runState)
{
    RunState = runState;
    int key = RUNSTATE_KEY;
    telemetryMapUpdateElem(mapFds[RUNSTATE_INDEX], &key, &runState, MAP_UPDATE_CREATE_OR_OVERWRITE);
}

//--------------------------------------------------------------------
//
// ~EbpfTracerEngine
//
// Destructor for the eBPF tracer engine.
//
//--------------------------------------------------------------------
EbpfTracerEngine::~EbpfTracerEngine()
{
    EventQueue.cancel();
    PollingThread.join();
    ConsumerThread.join();
}

//--------------------------------------------------------------------
//
// PerfCallbackWrapper
//
// Wrapper for the PerfCallback function. Called when new events
// arrive in the perf buffer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfCallbackWrapper(/* EbpfTracerEngine* */void *cbCookie, int cpu, void* rawMessage, uint32_t rawMessageSize)
{
    static_cast<EbpfTracerEngine *>(cbCookie)->PerfCallback(rawMessage, rawMessageSize);
}

//--------------------------------------------------------------------
//
// PerfCallback
//
// Called when new events arrive in the perf buffer.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfCallback(void *rawMessage, int rawMessageSize)
{
    EventQueue.push(*static_cast<SyscallEvent*>(rawMessage));
}

//--------------------------------------------------------------------
//
// PerfLostCallbackWrapper
//
// Lost events callback wrapper.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfLostCallbackWrapper(void *cbCookie, int cpu, uint64_t lost)
{
    static_cast<EbpfTracerEngine*>(cbCookie)->PerfLostCallback(lost);
}

//--------------------------------------------------------------------
//
// PerfLostCallback
//
// Lost events callback.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::PerfLostCallback(uint64_t lost)
{
    return;
}

//--------------------------------------------------------------------
//
// Poll
//
// Polls the perf buffer for new events.
//
//--------------------------------------------------------------------
void EbpfTracerEngine::Poll()
{
    bool btfEnabled = true;

    bool activeSyscalls[SYSCALL_ARRAY_SIZE];
    for(int i = 0; i < SYSCALL_ARRAY_SIZE; i++)
    {
        activeSyscalls[i] = false;
    }

    SetBootTime();

    const ebpfTelemetryObject   kernelObjs[] =
    {
        {
            KERN_4_17_5_1_OBJ, {4, 17}, {5, 2}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_2_OBJ, {5, 2}, {5, 3}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_3_5_5_OBJ, {5, 3}, {5, 6}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_6__OBJ, {5, 6}, {0, 0}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        }
    };

    ebpfTelemetryObject   kernelObjs_core[] =
    {
        {
            KERN_4_17_5_1_CORE_OBJ, {4, 17}, {5, 2}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_2_CORE_OBJ, {5, 2}, {5, 3}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_3_5_5_CORE_OBJ, {5, 3}, {5, 6}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        },
        {
            KERN_5_6__CORE_OBJ, {5, 6}, {0, 0}, true,
            0, NULL, 0, NULL, // No traditional tracepoint programs
            sizeof(RTPenterProgs) / sizeof(*RTPenterProgs),
            RTPenterProgs,
            sizeof(RTPexitProgs) / sizeof(*RTPexitProgs),
            RTPexitProgs,
            activeSyscalls,
            0, NULL
        }
    };

    const char* defPaths[] = {"./", "./procmonEBPF", "/tmp/"};

    const ebpfTelemetryConfig procmonConfig = (ebpfTelemetryConfig)
    {
        g_bootSecSinceEpoch,
        false, // enable raw socket capture
        btfEnabled ? sizeof(kernelObjs_core) / sizeof(*kernelObjs_core) : sizeof(kernelObjs) / sizeof(*kernelObjs),
        btfEnabled ? kernelObjs_core : kernelObjs,
        sizeof(defPaths) / sizeof(*defPaths),
        defPaths,
        sizeof(mapObjects) / sizeof(*mapObjects),
        mapObjects,
        NULL,
        debugTrace
    };

    const char* const argv[] = {"procmon"};

    setLogCallback(logHandler);

    int ret = telemetryStart(&procmonConfig, PerfCallbackWrapper, PerfLostCallbackWrapper, telemetryReady, configChange, this, (const char **)argv, mapFds);

    return;
}

//--------------------------------------------------------------------
//
// Consume
//
// Consumes the events from the event queue
//
//--------------------------------------------------------------------
void EbpfTracerEngine::Consume()
{
    //
    // We wait until sysinternalsEBPF is ready (telemetryReady is completed)
    //
    pthread_mutex_lock(&mutex);
    pthread_cond_wait(&cond, &mutex);
    pthread_mutex_unlock(&mutex);

    // blocking pop return optional<T>, evaluates to "true" if we get a value
    // "false" if we've been cancelled
    // auto stacks = BPF->get_stack_table("stack_traces");
    std::vector<ITelemetry> batch;
    size_t batchSize = 50;
    batch.reserve(batchSize);
    while (!EventQueue.isCancelled())
    {
        if(RunState == TRACER_STOP) break;

        if(RunState == TRACER_SUSPENDED)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        auto event = EventQueue.pop();

        if (!event.has_value())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (batch.size() >= batchSize)
        {
            auto res = _storageEngine->StoreMany(batch);
            // Free memory used for the arguments
            for (ITelemetry& datam: batch)
            {
                free(datam.arguments);
                datam.arguments = NULL;
            }

            batch.clear();
        }

        std::string syscall;
        for(auto sys : syscalls)
        {
            if(sys.number == event->sysnum)
            {
                syscall = sys.name;
            }
        }

        ITelemetry tel;
        tel.pid = event->pid;
        tel.stackTrace = GetStackTraceForIPs(event->pid, event->userStack, event->userStackCount);
        tel.comm = std::string(event->comm);
        tel.processName = std::string(event->comm);
        tel.syscall = syscall;

        if((int64_t)event->ret < 0)
        {
            constexpr uint64_t sign_bits = ~uint64_t{} << 63;
            tel.result = (int)(-1 * (event->ret & sign_bits) + (event->ret & ~sign_bits));
        }
        else
        {
            tel.result = event->ret;
        }

        tel.duration = event->duration_ns;
        tel.arguments = (unsigned char*) malloc(MAX_BUFFER);
        if(tel.arguments == nullptr){
            LOG(ERROR) << "tell.arguments is NULL";
            return;
        }

        memset(tel.arguments, 0, MAX_BUFFER);
        memcpy(tel.arguments, event->buffer, MAX_BUFFER);
        tel.timestamp = event->timestamp;

        batch.push_back(tel);
    }

    //
    // Cancel the sysinternalsEBPF polling loop
    //
    telemetryCancel();

    return;
}

//--------------------------------------------------------------------
//
// GetStackTraceForIPs
//
// Gets callstack. Since symbol resolution takes a substantial amount
// of time we only store the IPs during event processing, otherwise we
// end up saturating the perf buffer. When a user clicks into an event
// we resolve the symbols at that time.
//
//--------------------------------------------------------------------
StackTrace EbpfTracerEngine::GetStackTraceForIPs(int pid, uint64_t *userIPs, uint64_t userCount)
{
    StackTrace result;
    for (int i = 0; i < userCount; i++)
    {
        result.userIPs.push_back(userIPs[i]);
    }

    return result;
}

//--------------------------------------------------------------------
//
// AddPids
//
// Sets the pids to trace
//
//--------------------------------------------------------------------
void EbpfTracerEngine::AddPids(std::vector<int> pidsToTrace)
{
    for(int i=0; i<pidsToTrace.size(); i++)
    {
        telemetryMapUpdateElem(mapFds[PIDS_INDEX], &i, &pidsToTrace[i], MAP_UPDATE_CREATE_OR_OVERWRITE);
    }
}

