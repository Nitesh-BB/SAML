import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Res,
  Patch,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { CreateServiceProviderDto } from './dto/create-service-provider.dto';
import { UpdateServiceProviderDto } from './dto/update-service-provider.dto';
import { ServiceProviderService } from './service-provider.service';

@Controller('sp')
@ApiTags('service-provider')
export class ServiceProviderController {
  constructor(
    private readonly serviceProviderService: ServiceProviderService,
  ) {}

  @Post('create')
  async createSp(@Body() body: CreateServiceProviderDto) {
    return this.serviceProviderService.createSp(body);
  }

  @Get('metadata/:spId')
  async getMetaData(@Res() res: any, @Param('spId') spId: string) {
    const metadata = await this.serviceProviderService.getMetaData(spId);
    res.setHeader('Content-Type', 'text/xml');
    return res.send(metadata);
  }

  @Get('/all/:idpId')
  async getAllSp(@Param('idpId') idpId: string) {
    return this.serviceProviderService.getAllSp(idpId);
  }

  @Get('get/:spId')
  async getSp(@Param('spId') spId: string) {
    return this.serviceProviderService.getSp(spId);
  }

  @Delete('/:spId')
  async deleteSp(@Param('spId') spId: string) {
    return this.serviceProviderService.deleteSp(spId);
  }

  @Patch('/:spId')
  async updateSp(
    @Param('spId') spId: string,
    @Body() body: UpdateServiceProviderDto,
  ) {
    return this.serviceProviderService.updateSp(spId, body);
  }
}
