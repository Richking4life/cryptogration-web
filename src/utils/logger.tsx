/**
 * Logger Module
 * 
 * This module provides logging functionality with configurable log levels.
 * It allows logging messages at different levels (DEBUG, INFO, WARNING, ERROR),
 * and supports setting log levels dynamically based on the environment.
 */

// Determine environment and set log level accordingly
const environment: string = process.env.NODE_ENV || 'development'; // Default to development if NODE_ENV is not set

// Define log levels
const LOG_LEVELS = {
    DEBUG: 0,
    INFO: 1,
    WARNING: 2,
    ERROR: 3,
};

// Default log level
let logLevel: number = LOG_LEVELS.DEBUG;

/**
 * Set Log Level
 * 
 * Set the log level to control which messages get logged.
 * 
 * @param {number} level - The log level to set.
 * @throws {Error} If an invalid log level is provided.
 */
const setLogLevel = (level: number): void => {
    if (Object.values(LOG_LEVELS).includes(level)) {
        logLevel = level;
    } else {
        throw new Error("Invalid log level");
    }
};

/**
 * Log Message
 * 
 * Log a message at the specified log level.
 * 
 * @param {number} level - The log level.
 * @param {string} message - The message to log.
 */
const log = (level: number, message: string): void => {
    if (logLevel <= level) {
        // Perform logging based on the configured log level
        switch (level) {
            case LOG_LEVELS.DEBUG:
                // Placeholder: Log debug messages to your preferred mechanism
                // Example: Log debug messages to a file
                //  logToServer("DEBUG", message);
                if (environment !== 'production') console.debug(message);
                break;
            case LOG_LEVELS.INFO:
                // Placeholder: Log info messages to your preferred mechanism
                // Example: Log info messages to a logging service
                //  logToServer("INFO", message);
                if (environment !== 'production') console.info(message);
                break;
            case LOG_LEVELS.WARNING:
                // Placeholder: Log warning messages to your preferred mechanism
                // Example: Log warning messages to a database
                // logToServer("WARNING", message);
                if (environment !== 'production') console.warn(message);
                break;
            case LOG_LEVELS.ERROR:
                // Placeholder: Log error messages to your preferred mechanism
                // Example: Log error messages to a centralized error tracking system
                // logToServer("ERROR", message);
                if (environment !== 'production') console.error(message);
                break;
            default:
            // Handle default log
        }
    }
};

/**
 * Logger Object
 * 
 * Exposes methods for logging at different levels and setting log level dynamically.
 */
const Logger = {
    debug: (message: string | Error): void => {
        const debugMessage = message instanceof Error ? message.message : String(message);
        log(LOG_LEVELS.DEBUG, debugMessage);
    },
    info: (message: string | Error): void => {
        const infoMessage = message instanceof Error ? message.message : String(message);
        log(LOG_LEVELS.INFO, infoMessage);
    },
    warning: (message: string | Error): void => {
        const warningMessage = message instanceof Error ? message.message : String(message);
        log(LOG_LEVELS.WARNING, warningMessage);
    },
    error: (error: string | Error): void => {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log(LOG_LEVELS.ERROR, errorMessage);
    },
    setLogLevel,
};


// Map environment names to log levels
const environmentLogLevels: { [key: string]: number } = {
    development: LOG_LEVELS.DEBUG,
    test: LOG_LEVELS.INFO,
    production: LOG_LEVELS.WARNING,
};

// Set log level based on environment
Logger.setLogLevel(environmentLogLevels[environment]);

/**
 * Log To Server
 * 
 * Placeholder function to log messages to a server.
 * Currently commented out and not implemented.
 * 
 * @param {string} level - The log level.
 * @param {string} message - The message to log.
 * @param {string} [serverEndpoint] - The server endpoint to send the log message.
 */
// const logToServer = (level: string, message: string, serverEndpoint?: string): void => {
//     // const logData = {
//     //     level,
//     //     message,
//     //     timestamp: new Date().toISOString()
//     // };

//     // axios.post(serverEndpoint, logData)
//     //     .then((response) => {
//     //         if (environment !== 'production') console.log('Log message sent to server:', response.data);
//     //     })
//     //     .catch((error) => {
//     //         if (environment !== 'production') console.error('Error sending log message to server:', error);
//     //     });
// };


export default Logger;

