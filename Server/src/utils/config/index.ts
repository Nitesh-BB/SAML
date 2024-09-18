import { Session } from '@nestjs/common';

export default () => ({
  port: parseInt(process.env.PORT, 10) || 4000,
  SessionSecret: process.env.SESSION_SECRET,
  database: {
    uri: process.env.MONGO_URI,
  },

  server: {
    url: process.env.SERVER_URL,
  },
});
