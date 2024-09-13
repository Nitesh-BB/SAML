import { Global, Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import {
  ServiceProvider,
  ServiceProviderSchema,
} from './entities/service-provider.entity';
import { ServiceProviderController } from './service-provider.controller';
import { ServiceProviderService } from './service-provider.service';

@Global()
@Module({
  controllers: [ServiceProviderController],
  providers: [ServiceProviderService],
  imports: [
    MongooseModule.forFeature([
      {
        name: ServiceProvider.name,
        schema: ServiceProviderSchema,
      },
    ]),
  ],
  exports: [ServiceProviderService],
})
export class ServiceProviderModule {
  constructor(
    private readonly serviceProviderService: ServiceProviderService,
  ) {}
}
