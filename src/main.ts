import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AppModule } from './app.module';
import config from './config/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  const appConfig = config().app;
  const host = appConfig.host;
  const port = appConfig.port;

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport: Transport.GRPC,
    options: {
      url: `${host}:${port}`,
      package: ['auth', 'dto'],
      protoPath: join(__dirname, 'proto/auth.proto'),
    },
  });

  await app.listen();
  logger.log(`Starting Samithiwat's auth service listening at port ${port}`);
}
bootstrap();
