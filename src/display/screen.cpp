/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "screen.h"
#include "event_formatter.h"
#include "kill_event_formatter.h"
#include "../logging/easylogging++.h"
#include "../common/telemetry.h"

#include <version.h>
#include <chrono>
#include <thread>
#include <set>

Screen::Screen()
{
    totalLines = 0;
    currentLine = 1;
    currentPage = 0;
    totalEvents = 0;
}

 #define MAX_BUFFER 128

Screen::~Screen() { }

void Screen::InitializeFormatters()
{
    // reserve enough space assuming we will have one formatter per syscall
    formatters.reserve(335);

    // ALWAYS keep the default formatter in the first slot of vector.
    EventFormatter* default_formatter = new EventFormatter;
    default_formatter->Initialize("", configPtr.get());
    formatters.push_back(default_formatter);

    // Formatter for the kill syscall
    KillEventFormatter* kill = new KillEventFormatter;
    kill->Initialize("kill", configPtr.get());
    formatters.push_back(kill);
}

void Screen::initScreen(std::shared_ptr<ProcmonConfiguration> config)
{
    configPtr = config;

    InitializeFormatters();

    root = initscr();           // start curses mode
    start_color();              // start color mode
    raw();                      // Line buffering disabled
    noecho();                   // disable character echo
    halfdelay(1);
    nodelay(stdscr, true);      // make user input nonblocking
    curs_set(0);                // turn off cursor on UI
    mousemask(ALL_MOUSE_EVENTS, NULL);      // get all mouse events

    getmaxyx(stdscr, screenH, screenW);     // get initial screen size

    // calculate column height for initial screen size
    columnHeight = screenH - HEADER_HEIGHT - FOOTER_HEIGHT;

    // calculate the total number of lines on the screen
    totalLines = columnHeight - 1;

    // calculate the number of events we need to ingest before we can turn off refresh
    eventRefreshThreshold = totalLines * 1000;

    // initialize colors for ncurses
    initColors();

    // set filter control to false for default no filter
    filterPromptActive = false;
    searchPromptActive = false;
    searchCount = 0;
    filter = "";

    LOG(DEBUG) << "ScreenH:" << screenH << "ScreenW:" << screenW << "Column Height:" << columnHeight;

    // start initializing UI components
    initHeader();
    initFooter();
    initDetailView();
    initColumnView();
    initStatView();
    initHelpView();
    initTimestampColumn();
    initPidColumn();
    initProcessColumn();
    initOperationColumn();
    initResultColumn();
    initDurationColumn();
    initDetailColumn();

    // draw everything to screen
    refreshScreen();
}

void Screen::run()
{
    int input, prevInput = 0;
    bool running = true;
    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();
    MEVENT mouseEvent;
    int scrollCount = 0;
    std::chrono::_V2::steady_clock::time_point previousTime = std::chrono::steady_clock::now();
    std::chrono::_V2::steady_clock::time_point currentTime;
    int nonRefreshCount = 0;
    int64_t duration = 0;

    LOG(DEBUG) << "Starting main UI thread";
    LOG(DEBUG) << "Event Threshold:" << eventRefreshThreshold;
    LOG(DEBUG) << "Tracing Events:" << config->events.size();

    // check to see if we are loading a trace file
    if(config->GetTraceFilePath().compare("") != 0)
    {
        std::tuple<uint64_t, std::string> startTime;             // start time of previous trace to be loaded from file

        // stop tracer
        config->GetTracer()->SetRunState(TRACER_STOP);

        // clear what was inserted into datastore
        if(!storageEngine->Clear())
        {
            LOG(ERROR) << "Database failed to clear";
            return;
        }

        // load up database file
        try
        {
            startTime = storageEngine->Load(config->GetTraceFilePath());

            // update footer
            drawFooterFkeys();
        }
        catch(const std::runtime_error& e)
        {
            // something has gone wrong in loading the DB file. Report back to user and exit procmon
            LOG(ERROR) << e.what();
            shutdownScreen();

            std::cerr << "Failed to load tracefile " << config->GetTraceFilePath() << " with error: " << e.what();
            exit(-1);
        }

        if(std::get<0>(startTime) == 0)
        {
            LOG(ERROR) << "Failed to load trace file" << config->GetTraceFilePath();
            return;
        }

        // update config start time so that all timestamps are visualized correctly
        config->SetStartTime(std::get<0>(startTime));
        config->SetEpocStartTime(std::get<1>(startTime));
    }

    // run main UI loop
    while(running)
    {
        // read from user
        input = getUserInput();

        // if we have an active filter echo
        if(filterPromptActive)
        {
            // check to see if user has entered something new
            if(input != ERR)
            {
                if(input >= ' ' && input <= '~')                    // all printable ASCII characters
                {
                    filter += (char)input;

                    // update footer
                    drawFilterPrompt(filter);
                }
                else
                {
                    switch(input)
                    {
                        case KEY_DC:
                        case KEY_BACKSPACE:
                            if(filter.size() > 0)
                            {
                                filter.pop_back();
                                drawFilterPrompt(filter);
                            }

                            // query datastore and print to screen
                            break;
                        case 27:    // Esc Key
                            filterPromptActive = false;
                            filter = "";
                            drawFooterFkeys();

                            // display events with no filter on from current page
                            eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                            displayEvents(eventList);
                            break;
                        case KEY_F(9):
                            running = false;
                            break;
                        case KEY_ENTER:
                        case 10:
                            drawFooterFkeys();
                            filterPromptActive = false;
                            break;
                    }
                }
            }
            else
            {
                // if we have read nothing this cycle but a KEY_RESIZE was on the last iteration the user has stopped moving the terminal
                if(prevInput == KEY_RESIZE)
                {
                    resize();

                    // refill page with filtered events
                    if(filter.size() > 0) eventList = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    else eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);

                    // display current page
                    displayEvents(eventList);
                }
                else if(((prevInput >= ' ' && prevInput <= '~') || (prevInput == KEY_DC || prevInput == KEY_BACKSPACE)) && filter.size() > 0)
                {
                    // query datastore and print to screen
                    eventList = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    displayEvents(eventList);
                }
            }

        }
        else if(searchPromptActive)
        {
            // check to see if user has entered something new
            if(input != ERR)
            {
                if(input >= ' ' && input <= '~')                    // all printable ASCII characters
                {
                    // update search
                    filter += (char)input;

                    // reset search count
                    searchCount = 0;

                    // update footer
                    drawSearchPrompt(filter, false);
                }
                else
                {
                    switch(input)
                    {
                        case KEY_DC:
                        case KEY_BACKSPACE:
                            if(filter.size() > 0)
                            {
                                // delete character from search
                                filter.pop_back();

                                // if we have an empty filter clear idlist and turn off search highlight
                                if(filter.size() == 0)
                                {
                                    idList.clear();
                                    setLineColor(currentLine, HIGHLIGHT_COLOR);
                                }

                                // reset search count
                                searchCount = 0;

                                // update footer
                                drawSearchPrompt(filter, false);
                            }
                            else
                            {
                                // we have an empty search query move currentline to top of page and highlight normally
                                setLineColor(currentLine, LINE_COLOR);
                                currentLine = 1;
                                setLineColor(currentLine, HIGHLIGHT_COLOR);
                                idList.clear();
                            }
                            break;

                        case 27:    // Esc Key
                            searchPromptActive = false;
                            filter = "";
                            idList.clear();
                            drawFooterFkeys();

                            // reset line highlight to normal
                            setLineColor(currentLine, HIGHLIGHT_COLOR);
                            break;

                        case KEY_F(3):
                            searchCount++;
                            displaySearchEvents(idList, searchCount);
                            LOG(DEBUG) << "idList Size: " << idList.size() << " searchCount: " << searchCount;
                            break;

                        case KEY_F(9):
                            running = false;
                            break;

                        case KEY_ENTER:
                        case 10:    // Enter Key
                            drawFooterFkeys();
                            searchPromptActive = false;
                            break;
                    }
                }
            }
            else
            {
                // if we have read nothing this cycle but a KEY_RESIZE was on the last iteration the user has stopped moving the terminal
                if(prevInput == KEY_RESIZE) {
                    resize();

                    // refill page with events
                    eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    displayEvents(eventList);

                    // display current iteration of search
                    displaySearchEvents(idList, searchCount);
                }

                // check to make sure that user has stopped entering into prompt
                else if(((prevInput >= ' ' && prevInput <= '~') || (prevInput == KEY_DC || prevInput == KEY_BACKSPACE)) && filter.size() > 0)
                {
                    // query datastore for matching event ids and move to line
                    idList = storageEngine->QueryIdsBySearch(filter, config->pids, screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    LOG(DEBUG) << "Search returned" << idList.size() << "results";

                    // display search event
                    displaySearchEvents(idList, searchCount);
                }
            }
        }
        else {
            switch(input)
            {
                // Handle scrolling events
                case KEY_UP:
                    if(columnSortViewActive) columnScrollUp();
                    else if (detailViewActive) break;
                    else scrollUp();
                    break;

                case KEY_DOWN:
                    if(columnSortViewActive) columnScrollDown();
                    else if (detailViewActive) break;
                    else scrollDown();
                    break;

                case KEY_PPAGE:
                    if (scrollCount < MAX_CONTINUOUS_SCROLL || prevInput != KEY_PPAGE)
                    {
                        pageUp();
                        (KEY_PPAGE == prevInput) ? scrollCount++ : scrollCount = 0;
                        if(detailViewActive) closeDetailView();
                    }
                    break;

                case KEY_NPAGE:
                    if (scrollCount < MAX_CONTINUOUS_SCROLL || prevInput != KEY_NPAGE)
                    {
                        pageDown();
                        (KEY_NPAGE == prevInput) ? scrollCount++ : scrollCount = 0;
                        if(detailViewActive) closeDetailView();
                    }
                    break;

                // ncurses key_enter or ascii value 10 for enter key
                case KEY_ENTER:
                case 10:
                    if (detailViewActive) closeDetailView();
                    else if (!columnSortViewActive) showDetailView();
                    else if (columnSortViewActive) {
                        closeColumnView();
                        toggleColumnSort((ScreenConfiguration::sort)columnSortLineSelection);
                    }

                    break;

                // Handle function key events
                case KEY_F(1):
                    if(helpViewActive) closeHelpView();
                    else showHelpView();
                    break;

                case KEY_F(2):
                    if (columnSortViewActive) closeColumnView();
                    else if (!detailViewActive) showColumnView();

                    break;

                case KEY_F(3):
                    searchPromptActive = true;
                    drawSearchPrompt(filter, false);
                    break;

                case KEY_F(4):
                    filterPromptActive = true;
                    drawFilterPrompt(filter);
                    break;

                case KEY_F(5):
                    // is procmon currently in suspended mode and we have not opened a trace file
                    if(config->GetTracer()->GetRunState() == TRACER_SUSPENDED  && config->GetTraceFilePath().compare("") == 0)
                    {
                        config->GetTracer()->SetRunState(TRACER_RUNNING);
                    }
                    else
                    {
                        config->GetTracer()->SetRunState(TRACER_SUSPENDED);
                    }

                    drawFooterFkeys();

                    break;

                case KEY_F(6):
                    // only export if we have generated a new tracefile and not opened one
                    if(config->GetTraceFilePath().compare("") == 0)
                    {
                        storageEngine->Export(std::make_tuple(config->GetStartTime(), config->GetEpocStartTime()), config->GetOutputTraceFilePath());
                    }
                    break;

                case KEY_F(8):
                    if(statViewActive) closeStatView();
                    else showStatView();
                    break;

                // Quit Procmon
                case 'q':
                case KEY_F(9):
                    running = false;
                    break;

                // Esc Key
                case 27:
                    // close any view open
                    if (detailViewActive) closeDetailView();
                    else if (columnSortViewActive) closeColumnView();
                    else if (filterPromptActive) filterPromptActive = false;
                    else if (searchPromptActive) searchPromptActive = false;
                    else if (statViewActive) closeStatView();
                    else if (helpViewActive) closeHelpView();

                    drawFooterFkeys();
                    break;

                // handle mouse events
                case KEY_MOUSE:
                    if(getmouse(&mouseEvent) == NCURSES_OK) handleMouseEvent(&mouseEvent);
                    if(detailViewActive) showDetailView();
                    break;

                // CTRL + END
                case 530:
                    // if the number of events is evenly divisible then the last "page" has nothing to visualize
                    if (storageEngine->Size() % totalLines == 0)
                    {
                        currentPage = storageEngine->Size() / totalLines - 1;
                    }
                    else
                    {
                        currentPage = storageEngine->Size() / totalLines;
                    }
                    filter = "";

                    // get last page of events
                    eventList = storageEngine->QueryByEventsinPage(config->pids, currentPage, getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    displayEvents(eventList);
                    break;

                // CTRL + HOME
                case 535:
                    currentPage = 0;

                    // get first page of events
                    eventList = storageEngine->QueryByEventsinPage(config->pids, currentPage, getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                    displayEvents(eventList);
                    break;

                // no character was read this iteration
                case ERR:
                {
                    // if we have read nothing this cycle but a KEY_RESIZE was on the last iteration the user has stopped moving the terminal
                    if(prevInput == KEY_RESIZE) {
                        resize();

                        // refill page with filtered events
                        if(filter.size() > 0) eventList = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                        else eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                        displayEvents(eventList);
                    }
                    break;
                }

                default:
                    if (input != ERR)
                        LOG(DEBUG) << "Not in switch statement" << input;
            }
        }

        // save previous key to prevent scrolling of death
        prevInput = input;

        duration = std::chrono::duration_cast<std::chrono::milliseconds>((currentTime = std::chrono::steady_clock::now()) - previousTime).count();

        if((filter.size() == 0) &&                                         // is there no active filter or search?
            (duration > 1000))                                             // 1 second refresh on events
        {
            // attempt refresh only if under max tries or if the current page is not full
            if(nonRefreshCount < MAX_REFRESH_ATTEMPTS || (totalEvents < getTotalLines() && config->GetTracer()->GetRunState() == TRACER_RUNNING))
            {
                // check if there are any changes that need to be displayed
                auto newEventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
                int i = 0;

                LOG(DEBUG) << "New Eventlist Size" << newEventList.size();

                if(newEventList.size() > eventList.size())
                {
                    eventList.clear();
                    eventList = newEventList;
                    displayEvents(eventList);
                    nonRefreshCount = 0;
                }
                else
                {
                    for(; i < newEventList.size(); i++)
                    {
                        if(newEventList[i] != eventList[i])
                        {
                            eventList.clear();
                            eventList = newEventList;
                            displayEvents(eventList);
                            nonRefreshCount = 0;
                        }
                    }

                    // if we have iterated over the entire list then no refresh is needed
                    if(i >= newEventList.size())
                    {
                        LOG(DEBUG) << "No refresh needed";
                        nonRefreshCount++;
                    }
                }
            }
            previousTime = currentTime;
        }

        // draw events in datastore to screen
        windowPrintFillRight(headerWin, HEADER_COLOR, 0, HEADER_HEIGHT-1, "%-22s%10d%-5s", config->GetEpocStartTime().c_str(), storageEngine->Size(), "");

        // refresh entire window
        refreshScreen();

        // sleep UI thread for 10ms
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void Screen::shutdownScreen()
{
    // delete all windows created
    delwin(headerWin);
    delwin(footerWin);
    delwin(detailWin);
    delwin(statWin);
    delwin(helpWin);

    // delete all columns created
    timeStampColumn->~Column();
    pidColumn->~Column();
    processColumn->~Column();
    operationColumn->~Column();
    resultColumn->~Column();
    durationColumn->~Column();
    detailColumn->~Column();

    // free formatters
    for (std::vector<EventFormatter*>::iterator it = formatters.begin() ; it != formatters.end(); ++it)
    {
        free((*it));
    }

    // end curses mode
    endwin();
}

int Screen::getUserInput()
{
    return wgetch(headerWin);
}

void Screen::initColors()
{
    init_pair(HEADER_COLOR, COLOR_BLACK, COLOR_WHITE);
    init_pair(MENU_COLOR, COLOR_BLACK, LIGHT_BLUE);
    init_pair(COLUMN_HEADER_COLOR, COLOR_BLACK, BLUE);
    init_pair(LINE_COLOR, COLOR_WHITE, COLOR_BLACK);
    init_pair(HIGHLIGHT_COLOR, COLOR_BLACK, COLOR_CYAN);
    init_pair(SEARCH_HIGHLIGHT_COLOR, COLOR_BLACK, COLOR_YELLOW);
    init_pair(MENU_COLOR_ERROR, COLOR_RED, LIGHT_BLUE);
}

void Screen::initHeader()
{
    // create header window and panel
    headerWin = newwin(HEADER_HEIGHT, screenW, HEADER_Y, HEADER_X);
    headerPanel = new_panel(headerWin);

    // draw header to screen
    drawHeader();
}

void Screen::drawHeader()
{
    if(headerWin == NULL)
    {
        LOG(ERROR) << "Header must be initialized before you can draw it to the screen";
        exit(1);
    }

    // set background of window
    wbkgdset(headerWin, COLOR_PAIR(HEADER_COLOR));

    windowPrintFillRight(headerWin, HEADER_COLOR, 0, 0, "%-15s%10s%-5s", "Start Time:", "", "Total Events:");

    // move cursor to beginning of window
    wmove(headerWin, 0, 0);

    // write header to screen
    wprintw(headerWin, ">>> ProcessMonitor (%s) <<<", STRFILEVER);

    // enable fkeys on header window
    keypad(headerWin, true);

    // refresh header window
    wrefresh(headerWin);
}

void Screen::initFooter()
{
    footerWin = newwin(FOOTER_HEIGHT, screenW, screenH - 1, FOOTER_X);
    if(footerWin == nullptr){
        LOG(ERROR) << "footerWin is NULL";
        return;
    }
    
    footerPanel = new_panel(footerWin);
    if(footerPanel == nullptr) {
        LOG(ERROR) << "footerPanel is NULL";
        return;
    }

    // print f-key controls
    drawFooterFkeys();
}

void Screen::drawFooterFkeys()
{
    // move cursor to beginning of window
    wmove(footerWin, 0, 0);

    // set background of window
    wbkgdset(footerWin, COLOR_PAIR(MENU_COLOR));

    // setup window colors
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));

    // Add function key labels
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F1");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Help");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F2");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Sort By");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F3");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Search");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F4");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Filter");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F5");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));

    if(configPtr->GetTracer()->GetRunState() == TRACER_RUNNING)
    {
        wprintw(footerWin, " Suspend");
    }
    else
    {
        wprintw(footerWin, " Resume");
    }

    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F6");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Export");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F8");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Stats");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F9");
    windowPrintFill(footerWin, MENU_COLOR, getcurx(footerWin), 0, " Quit");

    // refresh footer window
    wrefresh(footerWin);
}

void Screen::drawFilterPrompt(std::string filter)
{
    // move cursor to beginning of window
    wmove(footerWin, 0, 0);

    // add filter labels
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " Enter");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Done");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " Esc");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Clear  ");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, "  ");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Filter: ");

    // add filter prompt
    windowPrintFill(footerWin, MENU_COLOR, getcurx(footerWin), 0, "%s", filter.c_str());

    // refresh footer window
    wrefresh(footerWin);
}

void Screen::drawSearchPrompt(std::string search, bool error)
{
    // move cursor to beginning of window
    wmove(footerWin, 0, 0);

    // add filter labels
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " F3");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Next");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " Esc");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Cancel  ");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, "  ");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Search: ");

    // add filter prompt
    if(error) windowPrintFill(footerWin, MENU_COLOR_ERROR, getcurx(footerWin), 0, "%s", filter.c_str());
    else windowPrintFill(footerWin, MENU_COLOR, getcurx(footerWin), 0, "%s", filter.c_str());

    // refresh footer window
    wrefresh(footerWin);
}

void Screen::initTimestampColumn()
{
    timeStampColumn = new Column(columnHeight, DEFAULT_TIME_COL_WIDTH, HEADER_HEIGHT, 0, " Timestamp");
    columnMap[ScreenConfiguration::time] = timeStampColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::time) timeStampColumn->toggleHeaderHighlight();
}

void Screen::initPidColumn()
{
    pidColumn = new Column(columnHeight, DEFAULT_PID_COL_WIDTH, HEADER_HEIGHT, DEFAULT_PID_COL_X, " PID");
    columnMap[ScreenConfiguration::pid] = pidColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::pid) pidColumn->toggleHeaderHighlight();
}

void Screen::initProcessColumn()
{
    processColumn = new Column(columnHeight, DEFAULT_PROCESS_COL_WIDTH, HEADER_HEIGHT, DEFAULT_PROCESS_COL_X, " Process");
    columnMap[ScreenConfiguration::process] = processColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::process) processColumn->toggleHeaderHighlight();
}

void Screen::initOperationColumn()
{
    operationColumn = new Column(columnHeight, DEFAULT_OPERATION_COL_WIDTH, HEADER_HEIGHT, DEFAULT_OPERATION_COL_X, " Operation");
    columnMap[ScreenConfiguration::operation] = operationColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::operation) operationColumn->toggleHeaderHighlight();
}

void Screen::initResultColumn()
{
    resultColumn = new Column(columnHeight, DEFAULT_RESULT_COL_WIDTH, HEADER_HEIGHT, DEFAULT_RESULT_COL_X, " Result");
    columnMap[ScreenConfiguration::result] = resultColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::result) resultColumn->toggleHeaderHighlight();
}

void Screen::initDurationColumn()
{
    durationColumn = new Column(columnHeight, DEFAULT_DURATION_COL_WIDTH, HEADER_HEIGHT, DEFAULT_DURATION_COL_X, " Duration (ms)");
    columnMap[ScreenConfiguration::duration] = durationColumn;

    // toggle header highlight based on screen configuration
    if(screenConfig.getColumnSort() == ScreenConfiguration::duration) durationColumn->toggleHeaderHighlight();
}

void Screen::initDetailColumn()
{
    detailColumn = new Column(columnHeight, screenW - DEFAULT_DETAIL_COL_X, HEADER_HEIGHT, DEFAULT_DETAIL_COL_X, " Details");
}

void Screen::initStatView()
{
    int statWindowHeight = DEFAULT_STAT_VIEW_HEIGHT;
    int statWindowWidth = screenW * 2 / 3;
    int statWindow_Y = screenH / 4;
    int statWindow_X = screenW / 6;

    statWin = newwin(statWindowHeight, statWindowWidth, statWindow_Y, statWindow_X);
    if(statWin == nullptr){
        LOG(ERROR) << "statWin is NULL";
        return;
    }

    statPanel = new_panel(statWin);
    if(statPanel == nullptr){
        LOG(ERROR) << "statPanel is NULL";
        return;
    }
    statViewActive = false;

    hide_panel(statPanel);
}

void Screen::initHelpView()
{
    int helpWindowHeight = DEFAULT_HELP_VIEW_HEIGHT;
    int helpWindowWidth = screenW * 2 / 3;
    int helpWindow_Y = screenH / 4;
    int helpWindow_X = screenW / 6;

    helpWin = newwin(helpWindowHeight, helpWindowWidth, helpWindow_Y, helpWindow_X);
    if(helpWin == nullptr){
        LOG(ERROR) << "helpWin is NULL";
        return;
    }

    helpPanel = new_panel(helpWin);
    if(helpPanel == nullptr){
        LOG(ERROR) << "helpPanel is NULL";
        return;
    }
    
    helpViewActive = false;

    hide_panel(helpPanel);
}


void Screen::initDetailView()
{
    int detailWindowHeight = screenH / 2;
    int detailWindowWidth = screenW * 2 / 3;
    int detailWindow_Y = screenH / 4;
    int detailWindow_X = screenW / 6;

    detailWin = newwin(detailWindowHeight, detailWindowWidth, detailWindow_Y, detailWindow_X);
    if(detailWin == nullptr){
        LOG(ERROR) << "detailWin is NULL";
        return;
    }

    detailPanel = new_panel(detailWin);
    if(detailPanel == nullptr){
        LOG(ERROR) << "detailPanel is NULL";
        return;
    }

    detailViewActive = false;

    hide_panel(detailPanel);
}

void Screen::initColumnView()
{
    int columnWindowHeight = DEFAULT_COLUMN_VIEW_HEIGHT;
    int columnWindowWidth = screenW * 2 / 3;
    int columnWindow_Y = screenH / 4;
    int columnWindow_X = screenW / 6;

    columnWin = newwin(columnWindowHeight, columnWindowWidth, columnWindow_Y, columnWindow_X);
    columnPanel = new_panel(columnWin);

    columnSortViewActive = false;

    hide_panel(columnPanel);
}

void Screen::scrollUp()
{
    // check if we are at the top of the page
    if(currentLine <= 1)                        // top of column values is 1 due to column header
    {
        // check if we are at the first page
        if(currentPage <= 0)
        {
            currentLine = 1;
        }
        else
        {
            // page up to go back to previous page
            pageUp();

            // set currentline to top of new page and adjust highlighting
            setLineColor(currentLine, LINE_COLOR);
            currentLine = totalLines;
            setLineColor(currentLine, HIGHLIGHT_COLOR);
        }
    }
    else
    {
        // highlight row above and set current line back to default
        setLineColor(currentLine, LINE_COLOR);
        currentLine--;
        setLineColor(currentLine, HIGHLIGHT_COLOR);
    }
    LOG(DEBUG) << "Screen scrollUp():::CurrentPage:\t" << currentPage << "CurrentLine:\t" << currentLine \
                << "totalEvents:\t" << totalEvents << "totalLines:\t" << totalLines;
}

void Screen::scrollDown()
{
    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();

    // check if we are at the bottom of the page and the page is full of events
    if(currentLine >= totalEvents)
    {
        // page down to scroll to next page if the current page is full
        if(totalEvents == totalLines)
        {
            int oldPage = currentPage;
            pageDown();

            if(currentPage > oldPage)
            {
                // update to top of new page and adjust highlighting
                setLineColor(currentLine, LINE_COLOR);
                currentLine = 1;
                setLineColor(currentLine, HIGHLIGHT_COLOR);
            }
        }
    }
    else
    {
        // highlight row below and set current line back to default
        setLineColor(currentLine, LINE_COLOR);
        currentLine++;
        setLineColor(currentLine, HIGHLIGHT_COLOR);
    }
    LOG(DEBUG) << "Screen scrollDown():::CurrentPage:\t" << currentPage << "CurrentLine:\t" << currentLine \
                << "totalEvents:\t" << totalEvents << "totalLines:\t" << totalLines;
}

void Screen::pageUp()
{
    // if we are at the first page then do nothing
    if (currentPage == 0) return;

    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();

    // decrement active page number
    currentPage--;

    // do we have an active filter?
    if (filter.size() > 0)
    {
        eventList = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
    }
    else
    {
        eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
    }

    // draw results from datastore to screen
    displayEvents(eventList);
}

void Screen::pageDown()
{
    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();

    // check if we have an active filter
    if(filter.size() > 0)
    {
        // can we scroll further?
        if(eventList.size() < totalLines)
        {
            auto newEventSet = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);

            // are there any new events with the current filter?
            if(newEventSet.size() > eventList.size())
            {
                eventList.clear();
                eventList.insert(eventList.end(), newEventSet.begin(), newEventSet.end());
            }
            else return;
        }
        else
        {
            // get filtered event set
            auto newEventSet = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage()+1, getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);

            // are the number of filtered events exactly divisible by totalLines
            if(newEventSet.size() != 0)
            {
                // increment active page number
                currentPage++;

                eventList.clear();
                eventList.insert(eventList.end(), newEventSet.begin(), newEventSet.end());
            }
            else return;
        }
    }
    else
    {
        // check to see if we are on the last page of events
        if (currentPage == (storageEngine->Size() / totalLines)) return;

        // increment active page number
        currentPage++;

        // get non filtered event set
        eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
    }

    // if the number of events to be displayed is less then current line move highlight to last line
    if(eventList.size() < currentLine)
    {
        currentLine = eventList.size();
    }

    // draw results from datastore to screen
    displayEvents(eventList);

    // highlight current line on new page
    setLineColor(currentLine, HIGHLIGHT_COLOR);
}

EventFormatter* Screen::GetFormatter(ITelemetry lineData)
{
    EventFormatter* ret = NULL;

    // Check to see if a formatter exists for this event
    for (std::vector<EventFormatter*>::iterator it = formatters.begin() ; it != formatters.end(); ++it)
    {
        if((*it)->GetSyscall().compare(lineData.syscall)==0)
        {
            ret=(*it);
            break;
        }
    }

    return ret;
}


int Screen::FindSyscall(std::string& syscallName)
{
    ProcmonConfiguration* config = configPtr.get();
    std::vector<struct SyscallSchema>& schema = config->GetSchema();

    int i=0;
    for(auto& syscall : schema)
    {
        if(syscallName.compare(syscall.syscallName)==0)
        {
            return i;
        }
        i++;
    }

    return -1;
}

void Screen::addLine(ITelemetry lineData)
{
    EventFormatter* format = GetFormatter(lineData);
    if(format == NULL)
    {
        // If we dont find a formatter for that syscall, use the default formatter.
        // Our default formatter is always the first item in the vector with a syscall name of ""
        std::vector<EventFormatter*>::iterator it = formatters.begin();
        format = (*it);
    }

    timeStampColumn->addLine(" " + format->GetTimestamp(lineData));
    pidColumn->addLine(" " + format->GetPID(lineData));
    processColumn->addLine(" " + format->GetProcess(lineData));
    operationColumn->addLine(" " + format->GetOperation(lineData));
    resultColumn->addLine(" " + format->GetResult(lineData));
    durationColumn->addLine(" " + format->GetDuration(lineData));
    detailColumn->addLine(" " + format->GetDetails(lineData));

    // increment total events on screen
    totalEvents++;

    // highlight line we are on if currentLine
    if(totalEvents == currentLine){
        setLineColor(totalEvents, HIGHLIGHT_COLOR);
    }
}

int Screen::getTotalEventsOnScreen()
{
    return totalEvents;
}

int Screen::getTotalLines()
{
    return totalLines;
}

int Screen::getCurrentPage()
{
    return currentPage;
}

void Screen::refreshScreen()
{
    // refresh each main window individually
    wnoutrefresh(headerWin);
    wnoutrefresh(footerWin);
    wnoutrefresh(detailWin);
    wnoutrefresh(columnWin);
    wnoutrefresh(statWin);
    wnoutrefresh(helpWin);

    // refresh columns
    timeStampColumn->refreshColumn();
    pidColumn->refreshColumn();
    processColumn->refreshColumn();
    operationColumn->refreshColumn();
    resultColumn->refreshColumn();
    durationColumn->refreshColumn();
    detailColumn->refreshColumn();

    // refresh panel stack
    update_panels();

    // write changes to screen
    doupdate();
}

void Screen::resize()
{
    // get new terminal size
    getmaxyx(stdscr, screenH, screenW);

    // calculate column height for initial screen size
    columnHeight = screenH - HEADER_HEIGHT - FOOTER_HEIGHT;

    // calculate the total number of lines on the screen
    totalLines = columnHeight - 1;

    // check to see if current highlight line is now off the screen
    if(totalLines < currentLine) currentLine = totalLines;

    LOG(DEBUG) << "Resize detected! ScreenH:" << screenH << "ScreenW:" << screenW << "Column Height:" << columnHeight;

    // resize header & footer
    resizeHeader();
    resizeFooter();

    // redraw header and footer
    drawHeader();

    if(filterPromptActive) drawFilterPrompt(filter);
    else if (searchPromptActive) drawSearchPrompt(filter, false);
    else drawFooterFkeys();

    // reset and clear current screen
    resetScreen();
    clearScreen();

    // resize columns
    timeStampColumn->resize(columnHeight, DEFAULT_TIME_COL_WIDTH, 0);
    pidColumn->resize(columnHeight, DEFAULT_PID_COL_WIDTH, DEFAULT_PID_COL_X);
    processColumn->resize(columnHeight, DEFAULT_PROCESS_COL_WIDTH, DEFAULT_RESULT_COL_X);
    operationColumn->resize(columnHeight, DEFAULT_OPERATION_COL_WIDTH, DEFAULT_RESULT_COL_X);
    resultColumn->resize(columnHeight, DEFAULT_RESULT_COL_WIDTH, DEFAULT_RESULT_COL_X);
    durationColumn->resize(columnHeight, DEFAULT_DURATION_COL_WIDTH, DEFAULT_DURATION_COL_X);
    detailColumn->resize(columnHeight, screenW - DEFAULT_DETAIL_COL_X, DEFAULT_DETAIL_COL_X);
}

void Screen::resizeHeader()
{
    if(wresize(headerWin, HEADER_HEIGHT, screenW) == ERR)
    {
        LOG(ERROR) << "Failed to resize header window";
        shutdownScreen();
        exit(1);
    }
}

void Screen::resizeFooter()
{
    if(mvwin(footerWin, screenH - 1, FOOTER_X) == ERR)
    {
        LOG(ERROR) << "Failed to move footer window";
        shutdownScreen();
        exit(1);
    }
    if(wresize(footerWin, FOOTER_HEIGHT, screenW) == ERR)
    {
        LOG(ERROR) << "Failed to resize footer window";
        shutdownScreen();
        exit(1);
    }
}



void Screen::resetScreen()
{
    // clear out all data in column objects
    timeStampColumn->resetColumn();
    pidColumn->resetColumn();
    processColumn->resetColumn();
    operationColumn->resetColumn();
    resultColumn->resetColumn();
    durationColumn->resetColumn();
    detailColumn->resetColumn();
}

void Screen::clearScreen()
{
    // clear out all data in column objects
    timeStampColumn->clearColumn();
    pidColumn->clearColumn();
    processColumn->clearColumn();
    operationColumn->clearColumn();
    resultColumn->clearColumn();
    durationColumn->clearColumn();
    detailColumn->clearColumn();

    // resent screen event counter
    totalEvents = 0;
}

void Screen::redrawScreen()
{
    // redraw events on screen
    timeStampColumn->redrawColumn();
    pidColumn->redrawColumn();
    processColumn->redrawColumn();
    operationColumn->redrawColumn();
    resultColumn->redrawColumn();
    durationColumn->redrawColumn();
    detailColumn->redrawColumn();

    // check to see if we have an active search
    if(idList.size() > 0) setLineColor(currentLine, SEARCH_HIGHLIGHT_COLOR);
    else setLineColor(currentLine, HIGHLIGHT_COLOR);
}

void Screen::displayEvents(std::vector<ITelemetry> eventList)
{
    // clear out what we have
    resetScreen();
    clearScreen();

    LOG(DEBUG) << "Length of eventlist to display" << eventList.size();

    // check if we have events to display
    if(eventList.size() <= 0)
    {
        return;
    }

    // display all events in vector
    for(int i = 0; i < eventList.size(); i++)
    {
        if(totalEvents < totalLines)
        {
            addLine(eventList[i]);
            refreshScreen();
        }
    }
}

void Screen::displaySearchEvents(std::vector<int> idList, int searchCount)
{
    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();

    // if we have a result set move screen to correct page
    if(idList.size() > 0 && searchCount < idList.size())
    {
        int id = idList[searchCount];
        int targetPage = id / getTotalLines();
        currentLine = id % getTotalLines();

        // columns are 1 based due to header string
        if(currentLine == 0)
        {
            targetPage--;
            currentLine = getTotalLines();
        }

        LOG(DEBUG) << "targetPage: " << targetPage << " currentLine: " << currentLine << " id: " << id << "TotalLines" << getTotalLines();

        // check if we actually need to query datastore or if its on the same page
        if(targetPage != currentPage)
        {
            currentPage = targetPage;
            eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
        }
        displayEvents(eventList);

        // highlight with search color
        setLineColor(currentLine, SEARCH_HIGHLIGHT_COLOR);
    }
    else
    {
        // we got an empty result set or at last event from the datastore
        drawSearchPrompt(filter, true);
    }
}

void Screen::toggleColumnSort(ScreenConfiguration::sort selectedColumn)
{
    ProcmonConfiguration * config = configPtr.get();
    auto storageEngine = config->GetStorage();
    ScreenConfiguration::sort columnSort = screenConfig.getColumnSort();

    // is this column currently selected?
    if(screenConfig.getColumnSort() == selectedColumn)
    {
        // column already highlighted so flip order
        screenConfig.toggleColumnAscending();
    }
    else
    {
        // update column highlighting
        columnMap[columnSort]->toggleHeaderHighlight();
        columnMap[selectedColumn]->toggleHeaderHighlight();

        // update current screen config
        screenConfig.setColumnSort(selectedColumn);

        // set column to sort by ascending
        screenConfig.setColumnAscending(true);
    }

    // query new events and display
    if (idList.size() > 0)
    {
        eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
        idList = storageEngine->QueryIdsBySearch(filter, config->pids, screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
        searchCount = 0;
        displaySearchEvents(idList, searchCount);
    }
    else if (filter.size() > 0)
    {
        eventList = storageEngine->QueryByFilteredEventsinPage(filter, config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
    }
    else
    {
        eventList = storageEngine->QueryByEventsinPage(config->pids, getCurrentPage(), getTotalLines(), screenConfig.getColumnSort(), screenConfig.getColumnAscending(), config->events);
    }
    displayEvents(eventList);
}

void Screen::showStatView()
{
    int y = 1;
    statViewActive = true;

    // move stat panel to front
    panel_above(statPanel);

    // print header
    windowPrintFill(statWin, COLUMN_HEADER_COLOR, 1, y, " Top 10 Syscall Statistics:");
    y++;

    // print column labels
    windowPrintFill(statWin, LINE_COLOR, 1, y, " %-20s %-15s %-15s", "Syscall:", "Count:", "Total Duration:");
    y++;

    // reset color
    wattron(statWin, COLOR_PAIR(LINE_COLOR));

    std::map<std::string, std::tuple<int, uint64_t>> syscallHitMap = configPtr->GetStorage()->GetHitmap();

	typedef std::function<bool(std::pair<std::string, std::tuple<int, uint64_t>>, std::pair<std::string, std::tuple<int, uint64_t>>)> Comparator;

	Comparator compFunctor =
			[](std::pair<std::string, std::tuple<int, uint64_t>> elem1 ,std::pair<std::string, std::tuple<int, uint64_t>> elem2)
			{
				return std::get<1>(elem1.second) > std::get<1>(elem2.second);
			};

    std::set<std::pair<std::string, std::tuple<int, uint64_t>>, Comparator> sortedSyscalls(syscallHitMap.begin(), syscallHitMap.end(), compFunctor);

    std::set<std::pair<std::string, std::tuple<int, uint64_t>>>::iterator it;
    for (it = sortedSyscalls.begin(); it != sortedSyscalls.end() && (y-2) <= 10; ++it)
    {
        // convert to milliseconds
        double duration = ((double)std::get<1>(it->second)) / 1000000;
        if(duration < 1.0)
        {
            windowPrintFill(statWin, LINE_COLOR, 1, y, " %-20s %-15d %.06f ms", it->first.c_str(), std::get<0>(it->second), duration);
        }
        else if (duration < 10.0)
        {
            windowPrintFill(statWin, LINE_COLOR, 1, y, " %-20s %-15d %.02f ms", it->first.c_str(), std::get<0>(it->second), duration);
        }
        else
        {
            windowPrintFill(statWin, LINE_COLOR, 1, y, " %-20s %-15d %.00f ms", it->first.c_str(), std::get<0>(it->second), duration);
        }
        y++;
    }

    // draw border
    box(statWin, '|', '_');

    refreshScreen();
}

void Screen::showHelpView()
{
    int y = 1;
    helpViewActive = true;

    // move help panel to front
    panel_above(helpPanel);

    // print header
    windowPrintFill(helpWin, COLUMN_HEADER_COLOR, 1, y, "%s %s", "Sysinternals - Procmon",  STRFILEVER);
    y+=2;

    // print column labels
    windowPrintFill(helpWin, LINE_COLOR, 1, y, " %-35s %-15s", "Arrows: scroll event list", "Enter: Display event properties");
    y++;

    windowPrintFill(helpWin, LINE_COLOR, 1, y, " %-35s %-15s", "F2: Sort by column", "F3: Search event list");
    y++;

    windowPrintFill(helpWin, LINE_COLOR, 1, y, " %-35s %-15s", "F4: Filter event list", "F5: Suspend/resume event collection");
    y++;

    windowPrintFill(helpWin, LINE_COLOR, 1, y, " %-35s %-15s", "F6: Export event list to file", "F8: Show stat of top syscalls");
    y++;

    windowPrintFill(helpWin, LINE_COLOR, 1, y, " %-35s", "F9: Quit");
    y++;

    box(helpWin, '|', '_');

    refreshScreen();
}


void Screen::closeStatView()
{
    // toggle stat view control
    statViewActive = false;

    // hide panel to remove from screen
    hide_panel(statPanel);

    // reprint footer
    drawFooterFkeys();

    // redraw & refresh screen
    redrawScreen();
    refreshScreen();
}

void Screen::closeHelpView()
{
    // toggle help view control
    helpViewActive = false;

    // hide panel to remove from screen
    hide_panel(helpPanel);

    // reprint footer
    drawFooterFkeys();

    // redraw & refresh screen
    redrawScreen();
    refreshScreen();
}


void Screen::showDetailView()
{
    int y = 1;
    ITelemetry * event;
    StackTrace * eventTrace;
    detailViewActive = true;
    int detailViewHeight = screenH / 2;

    // clear window
    werase(detailWin);

    // move detail panel to top to be visible
    panel_above(detailPanel);

    // Add header to detail view
    windowPrintFill(detailWin, COLUMN_HEADER_COLOR, 1, y++, "Event Properties");

    // reset color
    wattron(detailWin, COLOR_PAIR(LINE_COLOR));

    // retrieve event
    event = &eventList[currentLine - 1];

    // get event formatter for syscall
    EventFormatter * format = GetFormatter(*event);
    if(format == NULL)
    {
        // If we dont find a formatter for that syscall, use the default formatter.
        // Our default formatter is always the first item in the vector with a syscall name of ""
        std::vector<EventFormatter*>::iterator it = formatters.begin();
        format = (*it);
    }

    // add event details to window
    mvwprintw(detailWin, y++, 2, "%-19s%s", "Timestamp:", format->GetTimestamp(*event).c_str());
    mvwprintw(detailWin, y++, 2, "%-20s%s", "PID:", format->GetPID(*event).c_str());
    mvwprintw(detailWin, y++, 2, "%-20s%s", "Process:", format->GetProcess(*event).c_str());
    mvwprintw(detailWin, y++, 2, "%-20s%s", "Syscall:", format->GetOperation(*event).c_str());
    mvwprintw(detailWin, y++, 2, "%-20s%s", "Arguments:", format->GetDetails(*event).c_str());
    mvwprintw(detailWin, y++, 2, "%-20s%s", "Result:", format->GetResult(*event).c_str());

    mvwprintw(detailWin, y++, 2, "%-20s%s ns", "Duration:", format->GetDuration(*event).c_str());
    y++;

    // grab stack trace for current event
    eventTrace = &event->stackTrace;

    // Resolve symbols
    if(ResolveSymbols(eventTrace, event->pid))
    {
        mvwprintw(detailWin, y++, 2, "Stack Trace:");
        // add stack trace to window
        for(int i = 0; i < eventTrace->userIPs.size() && y < detailViewHeight - 1; i++)
        {
            mvwprintw(detailWin, y++, 4, "0x%-8lX %s", eventTrace->userIPs[i], eventTrace->userSymbols[i].c_str());
        }
    }

    // draw border
    box(detailWin, '|', '_');

    // refresh screen to draw window
    refreshScreen();
}

// ----------------------------------------------------------------------------
// ResolveSymbols
// ----------------------------------------------------------------------------
bool Screen::ResolveSymbols(StackTrace* stack, pid_t pid)
{
    void* symResolver = NULL;

    if (symEnginePidMap.find(pid) == symEnginePidMap.end())
    {
        symResolver = bcc_symcache_new(pid, &SymbolOption);
        symEnginePidMap[pid] = symResolver;

    }
    else
    {
        symResolver = symEnginePidMap[pid];
    }

    bcc_symbol symbol;
    for (int i = 0; i < stack->userIPs.size(); i++)
    {
        int ret = bcc_symcache_resolve(symResolver, stack->userIPs[i], &symbol);

        if (ret != 0)
        {
            if (symbol.module != NULL)
            {
                std::stringstream ss;
                ss << symbol.module << "![UNKNOWN]";
                stack->userSymbols.push_back(ss.str());
            }
            else
            {
                stack->userSymbols.push_back("[UNKNOWN]");
            }
        }
        else
        {
            std::stringstream ss;
            ss << symbol.module << "!" << symbol.demangle_name;
            stack->userSymbols.push_back(ss.str());
        }
    }

    return true;
}

void Screen::closeDetailView()
{
    // toggle detail view control
    detailViewActive = false;

    // hide panel to remove from screen
    hide_panel(detailPanel);

    // redraw & refresh screen
    redrawScreen();
    refreshScreen();
}

void Screen::showColumnView()
{
    // y coordinate for adding strings to screen, start 1 due to box border
    int y = 1;

    // enable view flag
    columnSortViewActive = true;

    // move column panel to top to be visible
    panel_above(columnPanel);

    // Add header to column view
    windowPrintFill(columnWin, COLUMN_HEADER_COLOR, y, 1, " Select Column");
    y++;

    // draw columns labels to window
    for(std::map<ScreenConfiguration::sort, Column*>::iterator iter=columnMap.begin();
                iter != columnMap.end();
                iter++)
    {
        // highlight current column selected
        if(iter->first == (int)screenConfig.getColumnSort())
        {
            windowPrintFill(columnWin, HIGHLIGHT_COLOR, 1, y, "%s", iter->second->getColumnName().c_str());
            columnSortLineSelection = (int)iter->first;
        }
        else windowPrintFill(columnWin, LINE_COLOR, 1, y, "%s", iter->second->getColumnName().c_str());
        y++;
    }

    // reset color
    wattron(columnWin, COLOR_PAIR(LINE_COLOR));

    // draw border
    box(columnWin, '|', '_');

    // update footer
    wmove(footerWin, 0, 0);


    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " Enter");
    wattron(footerWin, COLOR_PAIR(MENU_COLOR));
    wprintw(footerWin, " Done");
    wattron(footerWin, COLOR_PAIR(LINE_COLOR));
    wprintw(footerWin, " Esc");

    windowPrintFill(footerWin, MENU_COLOR, getcurx(footerWin), 0, " Close ");


    // refresh footer window
    wrefresh(footerWin);

    // refresh screen to draw window
    refreshScreen();
}

void Screen::closeColumnView()
{
    // toggle column view control
    columnSortViewActive = false;

    // hide panel to remove from screen
    hide_panel(columnPanel);

    // reprint footer
    drawFooterFkeys();

    // redraw & refresh screen
    redrawScreen();
    refreshScreen();
}

void Screen::columnScrollDown()
{
    // check if we are at the top of the page
    if(columnSortLineSelection < columnMap.size()-1)
    {
        windowPrintFill(columnWin, LINE_COLOR, 1, columnSortLineSelection + COLUMN_VIEW_Y_OFFSET, "%s", columnMap[(ScreenConfiguration::sort)(columnSortLineSelection)]->getColumnName().c_str());
        columnSortLineSelection++;
        windowPrintFill(columnWin, HIGHLIGHT_COLOR, 1, columnSortLineSelection + COLUMN_VIEW_Y_OFFSET, "%s", columnMap[(ScreenConfiguration::sort)(columnSortLineSelection)]->getColumnName().c_str());
    }

    // reset color
    wattron(columnWin, COLOR_PAIR(LINE_COLOR));
    box(columnWin, '|', '_');
}

void Screen::columnScrollUp()
{
    // check if we are at the bottom of the page
    if(columnSortLineSelection > 0)
    {
        // highlight row below and set current to default
        windowPrintFill(columnWin, LINE_COLOR, 1, columnSortLineSelection + COLUMN_VIEW_Y_OFFSET, "%s", columnMap[(ScreenConfiguration::sort)(columnSortLineSelection)]->getColumnName().c_str());
        columnSortLineSelection--;
        windowPrintFill(columnWin, HIGHLIGHT_COLOR, 1, columnSortLineSelection + COLUMN_VIEW_Y_OFFSET, "%s", columnMap[(ScreenConfiguration::sort)(columnSortLineSelection)]->getColumnName().c_str());
    }

    // reset color
    wattron(columnWin, COLOR_PAIR(LINE_COLOR));
    box(columnWin, '|', '_');
}

void Screen::setLineColor(int y, int colorPair)
{
    timeStampColumn->setLineColor(y, colorPair);
    pidColumn->setLineColor(y, colorPair);
    processColumn->setLineColor(y, colorPair);
    operationColumn->setLineColor(y, colorPair);
    resultColumn->setLineColor(y, colorPair);
    durationColumn->setLineColor(y, colorPair);
    detailColumn->setLineColor(y, colorPair);
}

void Screen::handleMouseEvent(MEVENT* event)
{
    switch(event->bstate)
    {
        case BUTTON1_PRESSED:
        case BUTTON1_CLICKED:
        case BUTTON1_DOUBLE_CLICKED:
        case BUTTON1_TRIPLE_CLICKED:
            LOG(DEBUG) << "Left mouse clicked at X: " << event->x << "\tY:" << event->y;

            // check if user is clicking on column headers
            if(event->y == HEADER_HEIGHT)
            {
                // check if timestamp header was clicked
                if(event->x > timeStampColumn->getX() && event->x < pidColumn->getX()) toggleColumnSort(ScreenConfiguration::time);
                else if(event->x > pidColumn->getX() && event->x < processColumn->getX()) toggleColumnSort(ScreenConfiguration::pid);
                else if(event->x > processColumn->getX() && event->x < operationColumn->getX()) toggleColumnSort(ScreenConfiguration::process);
                else if(event->x > operationColumn->getX() && event->x < resultColumn->getX()) toggleColumnSort(ScreenConfiguration::operation);
                else if(event->x > resultColumn->getX() && event->x < durationColumn->getX()) toggleColumnSort(ScreenConfiguration::result);
                else if(event->x > durationColumn->getX() && event->x < detailColumn->getX()) toggleColumnSort(ScreenConfiguration::duration);
            }
            // check if user is clicking on an event
            else if(event->y > HEADER_HEIGHT && event->y < screenH - 1 && event->y < (getTotalEventsOnScreen() + HEADER_HEIGHT))
            {
                // highlight selected line
                setLineColor(currentLine, LINE_COLOR);
                currentLine = event->y - pidColumn->getY();
                setLineColor(currentLine, HIGHLIGHT_COLOR);
            }
            break;

        default:
            LOG(DEBUG) << "Unknown mouse click";
            break;
    }
}

void Screen::windowPrintFill(WINDOW * win, int colorPair, int x, int y, const char * fmt, ...)
{
    int cursorX;
    int maximumX;

    // set background color
    wattron(win, COLOR_PAIR(colorPair));

    // move cursor to correct position
    wmove(win, y, x);

    // print to screen
    va_list args;
    va_start(args, fmt);
    vw_printw(win, fmt, args);
    va_end(args);

    // get current cursor position
    cursorX = getcurx(win);

    // get maximum window coordinates
    maximumX = getmaxx(win);


    // fill the rest of the line for screen
    for (int i = cursorX; i < maximumX; i++)
    {
        wprintw(win, " ");
    }
}

void Screen::windowPrintFillRight(WINDOW * win, int colorPair, int x, int y, const char * fmt, ...)
{
    int maximumX;
    char * buffer;

    // get maximum size of line
    maximumX = getmaxx(win);

    // allocate memory to print string
    buffer = (char*)malloc(sizeof(char) * maximumX);

    if(buffer == nullptr){
        LOG(ERROR) << "buffer is null";
        return;
    }

    // print string to buffer
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, maximumX, fmt, args);
    va_end(args);

    // set background color
    wattron(win, COLOR_PAIR(colorPair));

    // move cursor to correct position
    wmove(win, y, x);

    // fill left space to right align
    for(int i = 0; i < maximumX - strlen(buffer); i++)
    {
        wprintw(win, " ");
    }

    // print to screen
    wprintw(win, "%s", buffer);
    free(buffer);
}
