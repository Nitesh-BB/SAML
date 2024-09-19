import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { IdpModule } from './idp/idp.module';
import { ServiceProviderModule } from './service-provider/service-provider.module';
import config from './utils/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { CertificateModule } from './certificate/certificate.module';
import {
  configValidationOptions,
  configValidationSchema,
} from './utils/config/validation.config';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [config],
      validationSchema: configValidationSchema,
      validationOptions: configValidationOptions,
    }),
    MongooseModule.forRoot(process.env.MONGO_URI),
    IdpModule,
    ServiceProviderModule,
    CertificateModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
