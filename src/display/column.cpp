/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "column.h"
#include "screen.h"

Column::Column(int height, int width, int y, int x, std::string columnName)
{
    this->height = height;
    this->width = width;
    this->y = y;
    this->x = x;
    this->columnName = columnName;

    // init ncurses objects
    this->win = newwin(height, width, y, x);
    this->panel = new_panel(this->win);

    // init local column datastore
    this->columnData.clear();

    // Add Header to window
    columnPrintFill(COLUMN_HEADER_COLOR, 0, 0, "%s", (columnName + ":").c_str());

    this->currentLine = 1;                          // init to 1 to account for column header
    this->highlight = false;                        // init header highlight to off
    refreshColumn();
}

Column::~Column()
{
    // clean up column data
    this->columnData.clear();

    // free up ncurses objects
    del_panel(this->panel);
    delwin(this->win);
}

void Column::addLine(std::string value)
{
    // add data to local storage
    columnData.push_back(value);

    // write string to screen
    columnPrintFill(LINE_COLOR, 0, this->currentLine, "%s", value.c_str());
    this->currentLine++;
}

int Column::resize(int height, int width, int x)
{
    this->height = height;
    this->width = width;
    this->x = x;

    return wresize(this->win, height, width);
}

void Column::setLineColor(int y, int color)
{
    if(y - 1 < columnData.size())
    {
        columnPrintFill(color, 0, y, "%s", columnData[y - 1].c_str());
    }
}

void Column::toggleHeaderHighlight()
{
    if(highlight)
    {
        highlight = false;
        columnPrintFill(COLUMN_HEADER_COLOR, 0, 0, "%s", (columnName + ":").c_str());
    }
    else
    {
        highlight = true;
        columnPrintFill(HIGHLIGHT_COLOR, 0, 0, "%s", (columnName + ":").c_str());
    }
}

void Column::redrawColumn()
{
    int line = 0;

    // clear column
    clearColumn();

    // redraw header
    if(highlight) columnPrintFill(HIGHLIGHT_COLOR, 0, 0, "%s", (columnName + ":").c_str());
    else columnPrintFill(COLUMN_HEADER_COLOR, 0, 0, "%s", (columnName + ":").c_str());

    // redraw column data
    for(line = 0; line < this->height - 1 && line < columnData.size(); line++){
        columnPrintFill(LINE_COLOR, 0, line + 1, "%s", columnData[line].c_str());
    }
}

void Column::moveColumn(int x)
{
    this->x = x;
}

void Column::resetColumn()
{
    // reset line in column to 1
    currentLine = 1;

    // clear local column datastore
    this->columnData.clear();
}

void Column::clearColumn()
{
    // clear window
    werase(this->win);

    // redraw header
    if(highlight) columnPrintFill(HIGHLIGHT_COLOR, 0, 0, "%s", (columnName + ":").c_str());
    else columnPrintFill(COLUMN_HEADER_COLOR, 0, 0, "%s", (columnName + ":").c_str());
}

void Column::refreshColumn()
{
    wnoutrefresh(this->win);
}

void Column::hideColumn()
{
    hide_panel(this->panel);
}

void Column::showColumn()
{
    panel_above(this->panel);
}

void Column::columnPrintFill(int colorPair, int x, int y, const char * fmt, ...)
{
    int cursorX;

    // set background color
    wattron(this->win, COLOR_PAIR(colorPair));

    // move cursor to correct position
    wmove(win, y, x);

    // print to screen
    va_list args;
    va_start(args, fmt);
    std::string result;
    int len = vsnprintf(nullptr, 0, fmt, args)+1;
    va_end(args);

    if(len > 0)
    {
        result.resize(len);
        va_start(args, fmt);
        vsnprintf(&result.front(), len, fmt, args);
        va_end(args);
    }

    waddnstr(win, result.c_str(), this->width-COLUMN_PADDING);

    // get current cursor position
    cursorX = getcurx(win);

    if(cursorX <= this->width)
    {
        // fill the rest of the line for screen
        for (int i = cursorX; i < this->width; i++)
        {
            wprintw(win, " ");
        }
    }
}
