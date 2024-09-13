import { forwardRef, Global, Module } from '@nestjs/common';
import { IdpService } from './idp.service';
import { IdpController } from './idp.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Idp, IdpSchema } from './entities/idp.entity';
import { ServiceProviderModule } from 'src/service-provider/service-provider.module';
import { CertificateModule } from 'src/certificate/certificate.module';
import { SessionSchema } from './entities/session.entity';

@Global()
@Module({
  controllers: [IdpController],
  providers: [IdpService],
  imports: [
    CertificateModule,
    MongooseModule.forFeature([
      {
        name: Idp.name,
        schema: IdpSchema,
      },
      {
        name: 'sessions',
        schema: SessionSchema,
      },
    ]),
  ],
  exports: [IdpService],
})
export class IdpModule {
  constructor(private readonly idpService: IdpService) {}
}
