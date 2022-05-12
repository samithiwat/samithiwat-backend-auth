import * as dotenv from 'dotenv';
import { ConnectionOptions } from 'typeorm';

const envType = process.env.MODE_ENV || 'dev';

dotenv.config({ path: `.env.${envType}` });

const options: ConnectionOptions = {
  type: process.env.DATABASE_TYPE as any,
  host: process.env.DATABASE_HOST,
  port: parseInt(process.env.DATABASE_PORT) || 5432,
  database: process.env.DATABASE_NAME,
  username: process.env.DATABASE_USERNAME,
  password: process.env.DATABASE_PASSWORD,
  synchronize: false,
  entities: [process.env.ENTITY_PATH],
  migrations: [process.env.MIGRATION_PATH],
  migrationsRun: true,
  cli: {
    migrationsDir: 'src/database/migrations',
  },
};

export = options;
