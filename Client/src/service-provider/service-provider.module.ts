import { Module, OnModuleInit } from '@nestjs/common';
import { ServiceProviderService } from './service-provider.service';
import { ServiceProviderController } from './service-provider.controller';
import { HttpModule } from '@nestjs/axios';
import * as assert from 'assert';
import * as fs from 'fs';

@Module({
  controllers: [ServiceProviderController],
  providers: [ServiceProviderService],
  imports: [HttpModule],
})
export class ServiceProviderModule implements OnModuleInit {
  constructor(private readonly spService: ServiceProviderService) {}
  onModuleInit() {
    assert(
      process.env.IDP_METADATA_URL,
      'IDP_METADATA_URL is not defined, Please define it in .env file',
    );

    assert(
      fs.existsSync('./src/service-provider/sp-metadata.xml'),
      'sp-metadata.xml is not found, Please download it from Passwordess Dashboard',
    );

    this.spService.getSp();
    this.spService.getIdpMetadata();
  }
}
