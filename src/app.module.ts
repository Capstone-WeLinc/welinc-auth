import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import SharedModule from './shared/shared.module';
import AuthModule from './auth/auth.module';
import { HealthController } from './health/health.controller';
import { validateEnv } from './config/env';

@Module({
  imports: [
    // Spec 0010: the whole environment is checked here, before any module reads it
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    SharedModule,
    AuthModule,
  ],
  controllers: [AppController, HealthController],
  providers: [AppService],
})
export class AppModule {}
