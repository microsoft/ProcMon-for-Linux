/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SCREEN_H
#define SCREEN_H

#include <ncurses.h>

/*
 * Due to a conflict with ncurses OK macro and ebpf::StatusTuple::OK()
 * we have to undef OK and define a NCURSES_OK which is equivalent to
 * ncurses OK.
 */
#undef OK
#define NCURSES_OK 0

#include <panel.h>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "column.h"
#include "screen_configuration.h"
#include "event_formatter.h"
#include "../configuration/procmon_configuration.h"

// Symbol resolution code
#include "bcc_elf.h"
#include "bcc_perf_map.h"
#include "bcc_proc.h"
#include "bcc_syms.h"

// default screen dimensions
#define MINIMUM_HEIGHT  15
#define MINIMUM_WIDTH   100
#define HEADER_HEIGHT   2
#define FOOTER_HEIGHT   1
#define ROW_HEIGHT      1
#define DEFAULT_COLUMN_VIEW_HEIGHT  10
#define DEFAULT_STAT_VIEW_HEIGHT    15
#define DEFAULT_HELP_VIEW_HEIGHT    15

// default column sizes
#define DEFAULT_TIME_COL_WIDTH      15
#define DEFAULT_PID_COL_WIDTH       10
#define DEFAULT_PROCESS_COL_WIDTH   25
#define DEFAULT_OPERATION_COL_WIDTH 20
#define DEFAULT_DURATION_COL_WIDTH  20
#define DEFAULT_RESULT_COL_WIDTH    32

// default column X positions
#define DEFAULT_PID_COL_X           (int)DEFAULT_TIME_COL_WIDTH
#define DEFAULT_PROCESS_COL_X       (int)(DEFAULT_PID_COL_X + DEFAULT_PID_COL_WIDTH)
#define DEFAULT_OPERATION_COL_X     (int)(DEFAULT_PROCESS_COL_X + DEFAULT_PROCESS_COL_WIDTH)
#define DEFAULT_RESULT_COL_X        (int)(DEFAULT_OPERATION_COL_X + DEFAULT_OPERATION_COL_WIDTH)
#define DEFAULT_DURATION_COL_X      (int)(DEFAULT_RESULT_COL_X + DEFAULT_RESULT_COL_WIDTH)
#define DEFAULT_DETAIL_COL_X        (int)(DEFAULT_DURATION_COL_X + DEFAULT_DURATION_COL_WIDTH)

// default window positions
#define HEADER_X 0
#define HEADER_Y 0

// default color scheme
#define HEADER_COLOR                    1
#define MENU_COLOR                      2
#define COLUMN_HEADER_COLOR             3
#define LINE_COLOR                      4
#define HIGHLIGHT_COLOR                 5
#define DETAIL_VIEW_BACKGROUND_COLOR    6
#define SEARCH_HIGHLIGHT_COLOR          7
#define MENU_COLOR_ERROR                8

// default colors
#define LIGHT_BLUE  33
#define BLUE        35

#define FOOTER_X 0

#define MAX_CONTINUOUS_SCROLL   10
#define MAX_REFRESH_ATTEMPTS    5

// column view constants
#define COLUMN_VIEW_Y_OFFSET 2

class Screen {
    public:
        Screen();
        ~Screen();

        // public ncurses screen functions
        void initScreen(std::shared_ptr<ProcmonConfiguration>);
        void run();
        void shutdownScreen();
        void refreshScreen();

    private:
        // procmon configuration
        std::shared_ptr<ProcmonConfiguration> configPtr;

        // screen configuration
        ScreenConfiguration screenConfig;

        // screen variables
        int screenH;
        int screenW;
        int columnHeight;
        int totalLines;
        int currentLine;
        int currentPage;
        int eventRefreshThreshold;

        // event variables
        int totalEvents;

        // detail view dimensions
        int detailViewHeight;
        int detailViewWidth;

        // Stat view dimensions
        int statViewHeight;
        int statViewWidth;

        // Help view dimensions
        int helpViewHeight;
        int helpViewWidth;

        // control variables for various views
        bool detailViewActive;
        bool filterPromptActive;
        bool searchPromptActive;
        int searchCount;
        std::string filter;
        bool columnSortViewActive;
        int columnSortLineSelection;
        bool statViewActive;
        bool helpViewActive;

        // ncurses windows
        WINDOW* root;
        WINDOW* headerWin;
        WINDOW* footerWin;
        WINDOW* detailWin;
        WINDOW* columnWin;
        WINDOW* statWin;
        WINDOW* helpWin;

        // columns
        Column* timeStampColumn;
        Column* pidColumn;
        Column* processColumn;
        Column* operationColumn;
        Column* resultColumn;
        Column* durationColumn;
        Column* detailColumn;

        // column map
        std::map<ScreenConfiguration::sort, Column*> columnMap;

        // ncurses panels
        PANEL* headerPanel;
        PANEL* footerPanel;
        PANEL* detailPanel;
        PANEL* columnPanel;
        PANEL* statPanel;
        PANEL* helpPanel;

        // screen data
        std::vector<ITelemetry> eventList;
        std::vector<int> idList;

        // Symbol resolution
        std::unordered_map<int, void*> symEnginePidMap;
        bcc_symbol_option SymbolOption = {.use_debug_file = 1,
                                        .check_debug_file_crc = 1,
                                        .lazy_symbolize = 1,
                                        .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)};


        // A list of formatters used to special case the output formatting on a per sys call basis
        // NOTE: The first element in the vector is always our default formatter with a syscall name of "".
        //       When inserting formatters into this vector always push_back().
        std::vector<EventFormatter*> formatters;
        EventFormatter* GetFormatter(ITelemetry lineData);

        void InitializeFormatters();

        // Core Initializers
        void initColors();

        // Header Functions
        void initHeader();
        void drawHeader();
        void resizeHeader();

        // Footer Functions
        void initFooter();
        void drawFooterFkeys();
        void resizeFooter();

        // Footer View Functions
        void drawFilterPrompt(std::string filter);
        void drawSearchPrompt(std::string search, bool error);

        // View Initializers
        void initDetailView();
        void initColumnView();
        void initStatView();
        void initHelpView();

        // Column Initializers
        void initTimestampColumn();
        void initPidColumn();
        void initProcessColumn();
        void initOperationColumn();
        void initResultColumn();
        void initDurationColumn();
        void initDetailColumn();

        // Column visibility Control
        void hideColumns();
        void showColumns();

        // Terminal management helpers
        int getUserInput();
        void resize();

        // Display event helpers
        void addLine(ITelemetry lineData);
        void displayEvents(std::vector<ITelemetry> screenData);
        void displaySearchEvents(std::vector<int> idList, int searchCount);
        void toggleColumnSort(ScreenConfiguration::sort selectedColumn);
        int getTotalEventsOnScreen();
        int getTotalLines();
        int getCurrentPage();

        // Scrolling Helpers
        void scrollUp();
        void scrollDown();
        void pageUp();
        void pageDown();
        void columnScrollUp();
        void columnScrollDown();

        // View Controls
        void showDetailView();
        void closeDetailView();
        void showHelpView();
        void closeHelpView();
        void showColumnView();
        void closeColumnView();
        void showStatView();
        void closeStatView();

        // Mouse Helper Functions
        void handleMouseEvent(MEVENT* event);

        // Helper Functions
        void toggleColumnHighlight(ScreenConfiguration::sort selectedColumn);
        void windowPrintFill(WINDOW * win, int colorPair, int x, int y, const char * fmt, ...);
        void windowPrintFillRight(WINDOW * win, int colorPair, int x, int y, const char * fmt, ...);
        std::string calculateDeltaTimestamp(uint64_t ebpfEventTimestamp);
        bool compareEventList(std::vector<ITelemetry> newEventList, std::vector<ITelemetry> oldEventList);

        // Screen Control Functions
        void resetScreen();
        void clearScreen();
        void redrawScreen();
        void setLineColor(int y, int colorPair);

        std::string DecodeArguments(ITelemetry event);
        int FindSyscall(std::string& syscallName);
        bool ResolveSymbols(StackTrace* stack, pid_t pid);
};

#endif // SCREEN_H
