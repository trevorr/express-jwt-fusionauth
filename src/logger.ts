type LogFn = {
  (message: string, obj?: object): void;
};

/** Generic log message output interface. */
export interface Logger {
  /** Log a message at verbose level. */
  verbose: LogFn;
  /** Log a message at debug level. */
  debug: LogFn;
  /** Log a message at informational level. */
  info: LogFn;
  /** Log a message at warning level. */
  warn: LogFn;
  /** Log a message at error level. */
  error: LogFn;
}

/** @ignore */
const namespace = 'express-jwt-fusionauth';

/** @ignore */
const getConsoleLogger =
  (level: string): LogFn =>
  (message: string, ...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.log(level, namespace, message, ...args);
  };

/** @ignore */
const consoleLogger: Logger = {
  verbose: getConsoleLogger('VRB'),
  debug: getConsoleLogger('DBG'),
  info: getConsoleLogger('INF'),
  warn: getConsoleLogger('WRN'),
  error: getConsoleLogger('ERR')
};

/** @ignore */
let defaultLogger = consoleLogger;

import('debug')
  .then(Debug => {
    const debug = Debug.default(namespace);
    return (defaultLogger = {
      verbose: debug,
      debug,
      info: debug,
      warn: debug,
      error: debug
    });
  })
  .catch(
    /* istanbul ignore next */
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    () => {}
  );

/** Returns the default log message output interface. */
export function getDefaultLogger(): Logger {
  return defaultLogger;
}
