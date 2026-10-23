import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();

createApp(config).listen(config.port, config.host, () => {
  console.log(JSON.stringify({ level: 'info', message: 'web function listening', host: config.host, port: config.port }));
});
