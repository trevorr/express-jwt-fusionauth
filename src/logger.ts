/** Generic log message output interface. */
export interface Logger {
  /** Log a message at verbose level. */
  verbose(message: string): void;
  /** Log a message at debug level. */
  debug(message: string): void;
  /** Log a message at informational level. */
  info(message: string): void;
  /** Log a message at warning level. */
  warn(message: string): void;
  /** Log a message at error level. */
  error(message: string): void;
}

/** @ignore */
const namespace = 'express-jwt-fusionauth';

/** @ignore */
const getConsoleLogger = (level: string) => (message: string) => console.log(level, namespace, message);

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
