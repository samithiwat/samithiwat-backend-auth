import * as dotenv from 'dotenv';

const envType = process.env.NODE_ENV || 'dev';

dotenv.config({ path: `.env.${envType}` });

export default () => ({
  app: {
    host: process.env.HOST || 'localhost',
    port: parseInt(process.env.PORT) || 3001,
    origin: true,
  },
  user: {
    host: process.env.USER_SERVICE_HOST || 'localhost',
  },
  jwt: {
    secret: process.env.JWT_SECRET,
    tokenDuration: process.env.TOKEN_DURATION || '3600s',
  },
  database: {
    type: process.env.DATABASE_TYPE,
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT),
    name: process.env.DATABASE_NAME,
    username: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
  },
});
