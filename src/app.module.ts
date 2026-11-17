import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import SharedModule from './shared/shared.module';
import AuthModule from './auth/auth.module';
import { HealthController } from './health/health.controller';
import { validateEnv } from './config/env';
import { MonitoringModule } from './monitoring/monitoring.module';

@Module({
  imports: [
    // Spec 0010: the whole environment is checked here, before any module reads it
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    // Spec 0025: Sentry's request scope and the catch all filter. Before AuthModule, so its
    // CodeErrorFilter is registered later and still handles its own errors
    MonitoringModule,
    SharedModule,
    AuthModule,
  ],
  controllers: [AppController, HealthController],
  providers: [AppService],
})
export class AppModule {}
