/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <algorithm>
#include <functional>
#include <bits/stdc++.h>

#include "sqlite3_storage_engine.h"

#define SQL_CREATE_EBPF             "CREATE TABLE IF NOT EXISTS ebpf (    \
                                        pid INT,                          \
                                        stacktrace TEXT,                  \
                                        comm TEXT,                        \
                                        processname TEXT,                 \
                                        resultcode INTEGER,               \
                                        timestamp INTEGER,                \
                                        syscall TEXT,                     \
                                        duration INTEGER,                 \
                                        arguments BLOB                    \
                                    );"
#define SQL_CREATE_METADATA         "CREATE TABLE IF NOT EXISTS metadata (  \
                                        startTime INT,                      \
                                        startEpocTime TEXT                  \
                                    );"
#define SQL_CREATE_STATS            "CREATE TABLE IF NOT EXISTS stats ( \
                                        syscall TEXT,                   \
                                        count INTEGER,                  \
                                        duration INTEGER                \
                                    );"
#define SQL_SELECT_STARTTIME        "SELECT startTime, startEpocTime from metadata"
#define SQL_SELECT_STATS            "SELECT * FROM stats ORDER BY count LIMIT 10"
#define SQL_INSERT_METADATA         "INSERT into metadata (startTime, startEpocTime) VALUES (?, ?)"
#define SQL_INSERT_STATS            "INSERT into stats (syscall, count, duration) VALUES (?, ?, ?)"
#define SQL_CLEAR_EBPF              "DELETE FROM ebpf"
#define SQL_INITDB                  ":memory:"
#define SQL_DELIMITER               ", "
#define SQL_SELECT                  "SELECT pid, stacktrace, comm, processname, resultcode, timestamp, syscall, duration, arguments FROM ebpf"
#define SQL_SELECT_ID               "SELECT * FROM "
#define SQL_SELECT_ROWNUM(orderBy, asc) "SELECT ROW_NUMBER() OVER (ORDER BY " + orderBy + " " + asc
#define SQL_SELECT_ROWNUM_END       ") rownum, pid, processname, syscall, duration, resultcode FROM ebpf"
#define SQL_WHERE                   " WHERE "
#define SQL_CONTAIN_PID             "pid IN ("
#define SQL_CONTAIN_RESULTCODE      "resultcode IN ("
#define SQL_CONTAIN_SYSCALL         "syscall IN ("
#define SQL_NOT_CONTAIN_SYSCALL     "syscall NOT IN ("
#define SQL_CONTAIN_BEGIN           "("
#define SQL_CONTAIN_END             ")"
#define SQL_FILTER_TEXT(target)     " pid LIKE '%" + target + \
                                    "%' OR processname LIKE '%" + target + \
                                    "%' OR syscall LIKE '%" + target + \
                                    "%' OR duration LIKE '%" + target + \
                                    "%' OR resultcode LIKE '%" + target + "%'"
#define SQL_BETWEEN_TIME            "timestamp BETWEEN "
#define SQL_PAGINATE(offset, limit) " LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset)
#define SQL_INSERT                  "INSERT INTO ebpf (pid, stacktrace, comm, processname, resultcode, timestamp, syscall, duration, arguments) \
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
#define SQL_TX_START                "BEGIN TRANSACTION"
#define SQL_TX_END                  "END TRANSACTION"
#define SQL_TX_ROLLBACK             "ROLLBACK TRANSACTION"
#define SQL_AND                     " AND "
#define SQL_ORDER                   " ORDER BY "
#define SQL_ASCENDING               " ASC "
#define SQL_DESCENDING              " DESC "
#define SQL_END                     ";"

Sqlite3StorageEngine::~Sqlite3StorageEngine()
{
    telemetryCount = 0;
    ready = false;
    sqlite3_close(dbConnection);
}

/**
 * Initializes the Sqlite3 backend connection in serialized threading mode.
 *
 * Pre:
 *  The database connection isn't open and ready flag set to false.
 *
 * Post:
 *  Assuming the storage engine hasn't been initialized already, opens a
 *  Sqlite3 database connection for all data elements and set the ready
 *  flag to true.
 */
bool Sqlite3StorageEngine::Initialize(const std::vector<Event>& syscalls)
{
    if(ready)
        return false;

    // New storage engine new database connection.
    auto rc = sqlite3_open(SQL_INITDB, &dbConnection);
    if (rc != SQLITE_OK)
        return false;

    // We only create a single table for all events since there is no expected
    // perf gains by using a separate table for each syscall.
    rc = sqlite3_exec(dbConnection, SQL_CREATE_EBPF, 0, 0, nullptr);
    if (rc != SQLITE_OK)
        return false;

    // Create metadata table for traces
    rc = sqlite3_exec(dbConnection, SQL_CREATE_METADATA, 0, 0, nullptr);
    if (rc != SQLITE_OK)
        return false;

    // Create stat table for traces
    rc = sqlite3_exec(dbConnection, SQL_CREATE_STATS, 0, 0, nullptr);
    if (rc != SQLITE_OK)
        return false;

    // Copy constructors.
    syscallList = syscalls;

    telemetryCount = 0;
    ready = true;
    return ready;
}

/**
 * Internal helper method that parses a prepared SQL statement immediately after a sql
 * statement step call. This is done column by column and the extracted values are used
 * to construct a ITelemetry data element and returned.
 *
 * Pre:
 *  The given SQL statement a valid SQL SELECT statement, is prepared and associated to
 *  an open database connection.
 *
 * Post:
 *  Being only a retrieval, database should not be changed.
 *
 */
ITelemetry Sqlite3StorageEngine::parseSqlite3Row(sqlite3_stmt *preppedSqlStmt)
{
    ITelemetry datam
    {
        .pid = 0,
        .stackTrace = {},
        .comm = "",
        .processName = "",
        .syscall = "",
        .result = 0,
        .duration = 0,
        .arguments = NULL,
        .timestamp = 0
    };

    int columnCount = sqlite3_column_count(preppedSqlStmt);
    for (int i = 0; i < columnCount; i++)
    {
        std::string columnName (sqlite3_column_name(preppedSqlStmt, i));
        if (columnName == "pid")
        {
            datam.pid = sqlite3_column_int(preppedSqlStmt, i);
        }
        else if (columnName == "stacktrace")
        {
            // Add a way to capture stacktrace via a deserialize function.
            const char* stack = reinterpret_cast<const char*>(sqlite3_column_text(preppedSqlStmt, i));
            if (stack == NULL)
                continue;
            datam.stackTrace.Inflate(std::string(stack));
        }
        else if (columnName == "comm")
        {
            const char* comm = reinterpret_cast<const char*>(sqlite3_column_text(preppedSqlStmt, i));
            if (comm == NULL)
                continue;
            datam.comm = std::string(comm);
        }
        else if (columnName == "processname")
        {
            const char* processName = reinterpret_cast<const char*>(sqlite3_column_text(preppedSqlStmt, i));
            if (processName == NULL)
                continue;
            datam.processName = std::string(processName);
        }
        else if (columnName == "syscall")
        {
            const char* syscall = reinterpret_cast<const char*>(sqlite3_column_text(preppedSqlStmt, i));
            if (syscall == NULL)
                continue;
            datam.syscall = std::string(syscall);
        }
        else if (columnName == "resultcode")
        {
            datam.result = sqlite3_column_int64(preppedSqlStmt, i);
        }
        else if (columnName == "duration")
        {
            datam.duration = sqlite3_column_int64(preppedSqlStmt, i);
        }
        else if (columnName == "arguments")
        {
            const unsigned char* arguments = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(preppedSqlStmt, i));
            if (arguments == NULL)
                continue;

            // Interestingly enough, if we don't copy the blob we get back from sqlite it can eventually
            // reuse that memory buffer and change the contents of the record.
            datam.arguments = (unsigned char*) malloc(MAX_BUFFER);
            if(datam.arguments == nullptr){
                break; // I'm not sure if breaking is the right way of handling nullptr here.
            }
            memcpy(datam.arguments, arguments, MAX_BUFFER);
        }
        else if (columnName == "timestamp")
        {
            datam.timestamp = sqlite3_column_int64(preppedSqlStmt, i);
        }
    }

    return datam;
}

/**
 * Internal helper method that retrieves data from the Sqlite3 database by going through the
 * results step by step. This method relies on Sqlite3's locking mechanisms to deal with cases
 * where reads are happening at the same time that writes are happening.
 * Reads should not block other reads.
 *
 * Pre:
 *  The given SQL statement a valid SQL SELECT statement, is prepared and associated to
 *  an open database connection.
 *
 * Post:
 *  Being only a retrieval, database should not be changed.
 *
 */
std::vector<ITelemetry> Sqlite3StorageEngine::getFromSqlite3(sqlite3_stmt* preppedSqlStmt)
{
    std::vector<ITelemetry> results;

    auto rc = sqlite3_step(preppedSqlStmt);
    while (rc != SQLITE_DONE)
    {
        switch(rc)
        {
            case SQLITE_ROW:
            {
                ITelemetry datam = parseSqlite3Row(preppedSqlStmt);

                results.push_back(datam);
                rc = sqlite3_step(preppedSqlStmt);
                break;
            }

            case SQLITE_ERROR:
            {
                throw std::runtime_error{"Sqlite3 error encountered."};
            }
            case SQLITE_LOCKED:
            {
                // Sleep for 10ms and retry again...Consider something better later.
                sqlite3_sleep(10);
                continue;
            }
        }
    }
    return results;
}

std::vector<int> Sqlite3StorageEngine::getIdsFromSqlite3(sqlite3_stmt* preppedSqlStmt)
{
    std::vector<int> results;

    auto rc = sqlite3_step(preppedSqlStmt);
    while (rc != SQLITE_DONE)
    {
        switch(rc)
        {
            case SQLITE_ROW:
            {
                int id = sqlite3_column_int(preppedSqlStmt, 0);

                results.push_back(id);
                rc = sqlite3_step(preppedSqlStmt);
                break;
            }

            case SQLITE_ERROR:
            {
                throw std::runtime_error{"Sqlite3 error encountered retrieving row ids."};
            }
            case SQLITE_LOCKED:
            {
                // Sleep for 10ms and retry again...Consider something better later.
                sqlite3_sleep(10);
                continue;
            }
        }
    }
    return results;
}

/**
 * Internal helper method that prepares a SELECT SQL statement for database associated to the given syscall,
 * invokes the statement and then appends the resulting ITelemetry elements to given result vector.
 *
 * Pre:
 *  The database connection associated to the given syscall should already be open.
 *
 * Post:
 *  Being only a retrieval, database should not be changed.
 *
 */
// void Sqlite3StorageEngine::prepareAndGetFromSqlite3(std::vector<pid_t> pids, const std::vector<Event>& syscalls, std::vector<ITelemetry>& results)
void Sqlite3StorageEngine::prepareAndGetFromSqlite3(const std::string raw_sql_statement, std::vector<ITelemetry>& results)
{
    sqlite3_stmt* stmt;
    auto rc = sqlite3_prepare_v2(dbConnection, raw_sql_statement.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error{"Sqlite3 error encountered."};
    }

    try {
        auto temp = getFromSqlite3(stmt);

        // Move elements to result vector.
        results.insert(
            results.end(),
            std::make_move_iterator(temp.begin()),
            std::make_move_iterator(temp.end())
        );
    }
    catch (const std::runtime_error& e) {
        sqlite3_finalize(stmt);
        throw e;
    }
    sqlite3_finalize(stmt);
}

void Sqlite3StorageEngine::prepareAndGetIdsFromSqlite3(const std::string raw_sql_statement, std::vector<int>& results)
{
    sqlite3_stmt* stmt;
    auto rc = sqlite3_prepare_v2(dbConnection, raw_sql_statement.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error{"Sqlite3 error encountered in prepareAndGetIds."};
    }

    try {
        auto temp = getIdsFromSqlite3(stmt);

        // Move elements to result vector.
        results.insert(
            results.end(),
            std::make_move_iterator(temp.begin()),
            std::make_move_iterator(temp.end())
        );
    }
    catch (const std::runtime_error& e) {
        sqlite3_finalize(stmt);
        throw e;
    }
    sqlite3_finalize(stmt);
}

std::string Sqlite3StorageEngine::addPidFilterToSQLQuery(const std::string initialQuery, std::vector<pid_t> pids, const bool first)
{
    std::string resultingQuery = initialQuery;

    if (pids.size() > 0)
    {
        if (!first)
            resultingQuery += SQL_AND;
        else
            resultingQuery += SQL_WHERE;

        resultingQuery += SQL_CONTAIN_PID;

        // Construct delimited list of pids.
        std::string delimitedPids;
        for(std::vector<pid_t>::size_type i = 0; i < pids.size(); i++)
        {
            if (i != 0)
                delimitedPids += SQL_DELIMITER;
            delimitedPids += std::to_string(pids[i]);
        }
        resultingQuery += delimitedPids;
        resultingQuery += SQL_CONTAIN_END;
    }

    return resultingQuery;
}


std::string Sqlite3StorageEngine::addSyscallFilterToSQLQuery(const std::string initialQuery, std::vector<Event> events, const bool first)
{
    std::string resultingQuery = initialQuery;

    auto filterSize = events.size();
    auto maxSize = syscallList.size();

    if (filterSize < maxSize && filterSize > 0)
    {
        if (first)
            resultingQuery += SQL_AND;
        else
            resultingQuery += SQL_WHERE;

        resultingQuery += SQL_NOT_CONTAIN_SYSCALL;

        std::string delimitedSyscalls;

        // Use the contrapositive to create the filter instead.
        if (filterSize > maxSize/2)
        {
            std::vector<Event> difference;
            std::set_difference(syscallList.begin(), syscallList.end(), events.begin(), events.end(),
                                std::inserter(difference, difference.begin()));
            // Construct delimited list of syscalls.
            for(std::vector<pid_t>::size_type i = 0; i < difference.size(); i++)
            {
                if (i != 0)
                    delimitedSyscalls += SQL_DELIMITER;
                delimitedSyscalls += "'" + difference[i].Name() + "'";
            }
        }
        else
        {
            // Construct delimited list of syscalls.
            for(std::vector<pid_t>::size_type i = 0; i < events.size(); i++)
            {
                if (i != 0)
                    delimitedSyscalls += SQL_DELIMITER;
                delimitedSyscalls += "'" + events[i].Name() + "'";
            }
        }
        resultingQuery += delimitedSyscalls;
        resultingQuery += SQL_CONTAIN_END;
    }

    return resultingQuery;
}

std::vector<ITelemetry> Sqlite3StorageEngine::QueryByPid(pid_t pid, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, {pid}, true);
    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, false);
    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}

std::vector<ITelemetry> Sqlite3StorageEngine::QueryByPids(std::vector<pid_t> pids,
    const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, pids, true);

    auto first = true;
    if (pids.size() > 0)
        first = false;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, first);
    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}


std::vector<ITelemetry> Sqlite3StorageEngine::QueryByPidInTimespan(
    pid_t pid, double start_time, double end_time, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, {pid}, true);
    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, false);

    if (end_time - start_time > 0)
    {
        raw_sql_statement += SQL_AND;
        raw_sql_statement += SQL_BETWEEN_TIME;
        raw_sql_statement += std::to_string(start_time);
        raw_sql_statement += SQL_AND;
        raw_sql_statement += std::to_string(end_time);
    }

    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}

std::vector<ITelemetry> Sqlite3StorageEngine::QueryByPidsInTimespan(
    std::vector<pid_t> pids, double start_time, double end_time, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, pids, true);

    auto first = true;
    if (pids.size() > 0)
        first = false;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, first);

    if (end_time - start_time > 0)
    {
        raw_sql_statement += SQL_AND;
        raw_sql_statement += SQL_BETWEEN_TIME;
        raw_sql_statement += std::to_string(start_time);
        raw_sql_statement += SQL_AND;
        raw_sql_statement += std::to_string(end_time);
    }

    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}

std::vector<ITelemetry> Sqlite3StorageEngine::QueryByResultCodeInTimespan(
    int resultCode, double start_time, double end_time, const std::vector<Event> &syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = SQL_SELECT;
    raw_sql_statement += SQL_WHERE;
    raw_sql_statement += SQL_CONTAIN_RESULTCODE;
    raw_sql_statement += std::to_string(resultCode);
    raw_sql_statement += SQL_CONTAIN_END;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, false);

    if (end_time - start_time > 0)
    {
        raw_sql_statement += SQL_AND;
        raw_sql_statement += SQL_BETWEEN_TIME;
        raw_sql_statement += std::to_string(start_time);
        raw_sql_statement += SQL_AND;
        raw_sql_statement += std::to_string(end_time);
    }

    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}

/**
 * Primary querying function utilized by the UI to support column sorting both in
 * ascending and descending order.
 *
 * Pre:
 *  The database connection associated to the given syscall should already be open.
 *
 * Post:
 *  Being only a retrieval, database should not be changed.
 *
 */
std::vector<ITelemetry> Sqlite3StorageEngine::QueryByEventsinPage(
    std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, pids, true);

    auto first = true;
    if (pids.size() > 0)
        first = false;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, first);

    raw_sql_statement += SQL_ORDER;

    switch(orderBy)
    {
        case ScreenConfiguration::time:
            raw_sql_statement += "timestamp";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            break;
        case ScreenConfiguration::pid:
            raw_sql_statement += "pid";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::process:
            raw_sql_statement += "processname";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::operation:
            raw_sql_statement += "syscall";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::result:
            raw_sql_statement += "resultcode";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::duration:
            raw_sql_statement += "duration";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
    }

    uint offset = pageNumber * eventsPerPage;
    raw_sql_statement += SQL_PAGINATE(offset, eventsPerPage);

    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;
}

std::vector<ITelemetry> Sqlite3StorageEngine::QueryByFilteredEventsinPage(
    std::string filter, std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_sql_statement;

    raw_sql_statement = addPidFilterToSQLQuery(SQL_SELECT, pids, true);

    auto first = true;
    if (pids.size() > 0)
        first = false;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, first);

    // check to see if a PID filter or syscall filter is in place on procmon
    if (first) raw_sql_statement += SQL_WHERE;
    else raw_sql_statement += SQL_AND;

    // add text filter to results
    raw_sql_statement += SQL_FILTER_TEXT(filter);

    raw_sql_statement += SQL_ORDER;

    switch(orderBy)
    {
        case ScreenConfiguration::time:
            raw_sql_statement += "timestamp";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            break;
        case ScreenConfiguration::pid:
            raw_sql_statement += "pid";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::process:
            raw_sql_statement += "processname";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::operation:
            raw_sql_statement += "syscall";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::result:
            raw_sql_statement += "resultcode";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::duration:
            raw_sql_statement += "duration";
            raw_sql_statement += (asc) ? SQL_ASCENDING : SQL_DESCENDING;
            raw_sql_statement += ", timestamp ASC";
            break;
    }

    uint offset = pageNumber * eventsPerPage;
    raw_sql_statement += SQL_PAGINATE(offset, eventsPerPage);

    raw_sql_statement += SQL_END;

    std::vector<ITelemetry> results;
    prepareAndGetFromSqlite3(raw_sql_statement, results);

    return results;

}

std::vector<int> Sqlite3StorageEngine::QueryIdsBySearch(
    std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls)
{
    if(!ready)
        throw std::runtime_error{"Storage engine must be initialized first."};

    std::string raw_select_sql_statement;
    std::string raw_sql_statement;

    raw_select_sql_statement += SQL_SELECT_ID;
    raw_select_sql_statement += SQL_CONTAIN_BEGIN;

    switch(orderBy)
    {
        case ScreenConfiguration::time:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("timestamp"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("timestamp"), SQL_DESCENDING);
            break;
        case ScreenConfiguration::pid:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("pid"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("pid"), SQL_DESCENDING);
            raw_select_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::process:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("processname"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("processname"), SQL_DESCENDING);
            raw_select_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::operation:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("syscall"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("syscall"), SQL_DESCENDING);
            raw_select_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::result:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("resultcode"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("resultcode"), SQL_DESCENDING);
            raw_select_sql_statement += ", timestamp ASC";
            break;
        case ScreenConfiguration::duration:
            raw_select_sql_statement += (asc) ? SQL_SELECT_ROWNUM(std::string("duration"), SQL_ASCENDING) : SQL_SELECT_ROWNUM(std::string("duration"), SQL_DESCENDING);
            raw_select_sql_statement += ", timestamp ASC";
            break;
    }

    raw_select_sql_statement += SQL_SELECT_ROWNUM_END;
    raw_select_sql_statement += SQL_CONTAIN_END;

    raw_sql_statement = addPidFilterToSQLQuery(raw_select_sql_statement, pids, true);

    auto first = true;
    if (pids.size() > 0)
        first = false;

    raw_sql_statement = addSyscallFilterToSQLQuery(raw_sql_statement, syscalls, first);

    // check to see if a PID filter or syscall filter is in place on procmon
    if (first) raw_sql_statement += SQL_WHERE;
    else raw_sql_statement += SQL_AND;

    // add text filter to results
    raw_sql_statement += SQL_FILTER_TEXT(search);

    raw_sql_statement += SQL_END;

    std::vector<int> results;
    prepareAndGetIdsFromSqlite3(raw_sql_statement, results);

    return results;
}

/**
 * Implements interface method to store a single ITelemetry data entry. This method
 * should not be written to by more than one thread. If there is more than one writer
 * Sqlite3's internal lock(s) will cause the latter write to fail.
 *
 * Pre:
 *  The database connection is open and the storage engine is ready.
 *
 * Post:
 *  The database should contain one new entry if all constraints are met.
 *
 */
bool Sqlite3StorageEngine::Store(ITelemetry data)
{
    if (!ready) return false;

    // Update the syscallHitMap map to keep total running syscalls and durations. We store it here
    // in a shared map to avoid the cost of keeping an additional table. The map is sorted by duration
    // only when user requests it through the 'Stats' capability.
    if(_syscallHitMap.find(data.syscall) != _syscallHitMap.end())
    {
        std::tuple<int, uint64_t>* _syscallTuple = &_syscallHitMap[data.syscall];
        std::get<0>(*_syscallTuple)++;
        std::get<1>(*_syscallTuple) += data.duration;
    }
    else
    {
        _syscallHitMap.insert(std::make_pair(data.syscall, std::make_tuple(1, data.duration)));
    }

    // store syscall event in database
    sqlite3_stmt* stmt;
    auto rc = sqlite3_prepare_v2(dbConnection, SQL_INSERT SQL_END, -1, &stmt, nullptr);

    rc = rc & sqlite3_bind_int(stmt, 1, data.pid);

    auto serializedData = data.stackTrace.Serialize();

    rc = rc & sqlite3_bind_text(stmt, 2, serializedData.c_str(), serializedData.size()+1, nullptr);

    rc = rc & sqlite3_bind_text(stmt, 3, data.comm.c_str(), data.comm.size()+1, nullptr);

    rc = rc & sqlite3_bind_text(stmt, 4, data.processName.c_str(), data.processName.size()+1, nullptr);

    rc = rc & sqlite3_bind_int64(stmt, 5, data.result);

    rc = rc & sqlite3_bind_int64(stmt, 6, data.timestamp);

    rc = rc & sqlite3_bind_text(stmt, 7, data.syscall.c_str(), data.syscall.size()+1, nullptr);

    rc = rc & sqlite3_bind_int64(stmt, 8, data.duration);

    rc = rc & sqlite3_bind_blob(stmt, 9, data.arguments, MAX_BUFFER, SQLITE_STATIC);

    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        return false;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return false;

    telemetryCount++;

    return true;
}

/**
 * Implements interface method to store N ITelemetry data entries. This method
 * should not be written to by more than one thread. If there is more than one writer,
 * Sqlite3's internal lock(s) will cause the latter write to fail.
 *
 * If any to be added element doesnt meet the constraint, the full operation will terminate
 * with no elements having been added. This achieved by performing all writes within a single
 * SQL transaction, and by rolling back the transaction if a constraint is not met.
 *
 * Pre:
 *  The database connection is open and the storage engine is ready.
 *
 * Post:
 *  The database should contain data.size() new entry if all constraints are met.
 *
 */
bool Sqlite3StorageEngine::StoreMany(std::vector<ITelemetry> data)
{
    if(!ready || data.size() < 1)
        return false;

    sqlite3_exec(dbConnection, SQL_TX_START, NULL, NULL, nullptr);

    for (ITelemetry& datam: data)
    {
        if (!Store(datam))
        {
            sqlite3_exec(dbConnection, SQL_TX_ROLLBACK, NULL, NULL, nullptr);
            return false;
        }
    }
    sqlite3_exec(dbConnection, SQL_TX_END, NULL, NULL, nullptr);

    return true;
}

bool Sqlite3StorageEngine::Clear()
{
    bool ret = false;
    std::string clear_sql_statement;
    int rc;

    if(!ready)
        throw std::runtime_error("Storage engine must be initialized first");

    // prepare statement
    clear_sql_statement = SQL_CLEAR_EBPF; + SQL_END;

    sqlite3_exec(dbConnection, SQL_TX_START, NULL, NULL, nullptr);
    rc = sqlite3_exec(dbConnection, clear_sql_statement.c_str(), NULL, NULL, nullptr);
    sqlite3_exec(dbConnection, SQL_TX_END, NULL, NULL, nullptr);
    telemetryCount = 0;

    ret = (rc != SQLITE_OK) ? false : true;

    return ret;
}

int Sqlite3StorageEngine::Size()
{
    if(!ready)
        throw std::runtime_error("Storage engine must be initialized first.");

    return telemetryCount;
}

bool Sqlite3StorageEngine::Export(std::tuple<uint64_t, std::string> startTime, std::string filePath)
{
    bool ret = false;
    int rc = 0;
    sqlite3* pFile;
    sqlite3_backup* pBackup;
    sqlite3* pTo;
    sqlite3* pFrom;

    // metadata
    uint64_t clockStart = std::get<0>(startTime);
    std::string epocTime = std::get<1>(startTime);

    // store startime of trace in metadata table
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(dbConnection, SQL_INSERT_METADATA SQL_END, -1, &stmt, nullptr);

    rc = rc & sqlite3_bind_int64(stmt, 1, clockStart);
    rc = rc & sqlite3_bind_text(stmt, 2, epocTime.c_str(), epocTime.size()+1, nullptr);

    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        return false;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return false;

    // store stats of trace in stats table
    typedef std::function<bool(std::pair<std::string, std::tuple<int, uint64_t>>, std::pair<std::string, std::tuple<int, uint64_t>>)> Comparator;

	Comparator compFunctor =
			[](std::pair<std::string, std::tuple<int, uint64_t>> elem1 ,std::pair<std::string, std::tuple<int, uint64_t>> elem2)
			{
				return std::get<1>(elem1.second) > std::get<1>(elem2.second);
			};

    std::set<std::pair<std::string, std::tuple<int, uint64_t>>, Comparator> sortedSyscalls(_syscallHitMap.begin(), _syscallHitMap.end(), compFunctor);

    std::set<std::pair<std::string, std::tuple<int, uint64_t>>>::iterator it;
    int i;

    for (it = sortedSyscalls.begin(), i = 0; it != sortedSyscalls.end() && i < 10; ++it, i++)
    {
        sqlite3_stmt* stats;
        rc = sqlite3_prepare_v2(dbConnection, SQL_INSERT_STATS SQL_END, -1, &stats, nullptr);
        rc = rc & sqlite3_bind_text(stats, 1, it->first.c_str(), it->first.length() + 1, nullptr);
        rc = rc & sqlite3_bind_int(stats, 2, std::get<0>(it->second));
        rc = rc & sqlite3_bind_int64(stats, 3, std::get<1>(it->second));

        if (rc != SQLITE_OK)
        {
            sqlite3_finalize(stats);
            return false;
        }

        rc = sqlite3_step(stats);
        sqlite3_finalize(stats);

        if (rc != SQLITE_DONE)
            return false;
    }


    rc = sqlite3_open(filePath.c_str(), &pFile);
    if (rc == SQLITE_OK)
    {
        pBackup = sqlite3_backup_init(pFile, "main", dbConnection, "main");
        if (pBackup) {
            sqlite3_backup_step(pBackup, -1);
            sqlite3_backup_finish(pBackup);
            ret = true;
        }
    }
    else
    {
        throw std::runtime_error("Failed to open tracefile " + filePath);
    }


    sqlite3_close(pFile);

    return ret;
}

std::tuple<uint64_t, std::string> Sqlite3StorageEngine::Load(std::string filepath)
{
    sqlite3_stmt* stmt;
    uint64_t startTimeTicks;
    std::string startTimeEpoc;
    std::string columnName, syscall;
    int count;
    uint64_t duration;

    // clear syscall hitmap
    _syscallHitMap.clear();

    // close connection to in memory database
    auto rc = sqlite3_close(dbConnection);

    if(rc != SQLITE_OK) throw std::runtime_error{"Failed to disconnect from in-memory database"};

    // connect to exported DB to load events
    rc = sqlite3_open(filepath.c_str(), &dbConnection);
    if (rc != SQLITE_OK) throw std::runtime_error{"Failed to attach to DB file"};

    // update size value of storage engine to size of tracefile
    rc = sqlite3_prepare_v2(dbConnection, "SELECT COUNT(*) FROM ebpf;", -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error{"Failed to query DB for event count"};
    }

    if(sqlite3_step(stmt) == SQLITE_ROW) telemetryCount = sqlite3_column_int(stmt, 0);

    // extract stats information
    rc = sqlite3_prepare_v2(dbConnection, SQL_SELECT_STATS SQL_END, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error{"Failed to query DB for stats"};
    }

    // start iterating over stat resultset
    rc = sqlite3_step(stmt);

    while(rc != SQLITE_DONE)
    {
        switch(rc)
        {
            case SQLITE_ROW:
            {
                for(int i = 0; i < sqlite3_column_count(stmt); i++)
                {
                    columnName = sqlite3_column_name(stmt, i);
                    if (columnName == "syscall")
                    {
                        const char* _syscall = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                        if (_syscall == NULL)
                            continue;

                        syscall = std::string(_syscall);
                    }
                    else if(columnName == "count")
                    {
                        count = sqlite3_column_int(stmt, i);
                    }
                    else if(columnName == "duration")
                    {
                        duration = sqlite3_column_int64(stmt, i);
                    }
                }
                _syscallHitMap.insert(std::make_pair(syscall, std::make_tuple(count, duration)));
                rc = sqlite3_step(stmt);
                break;
            }
            case SQLITE_ERROR:
            {
                throw std::runtime_error{"Sqlite3 error encountered."};
            }
            case SQLITE_LOCKED:
            {
                // Sleep for 10ms and retry again...Consider something better later.
                sqlite3_sleep(10);
                continue;
            }
        }
    }
    sqlite3_finalize(stmt);

    // extract trace metadata and configure procmon
    rc = sqlite3_prepare_v2(dbConnection, SQL_SELECT_STARTTIME SQL_END, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw std::runtime_error{"Failed to query DB for metadata"};
    }

    if(sqlite3_step(stmt) == SQLITE_ROW)
    {
        startTimeTicks = sqlite3_column_int64(stmt, 0);
        const char* rawEpocTime = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        startTimeEpoc = std::string(rawEpocTime);

        return std::make_tuple(startTimeTicks, startTimeEpoc);
    }
    else
    {
        // return empty tuple on error
        return std::make_tuple(0, "");
    }
}