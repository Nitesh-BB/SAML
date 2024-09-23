import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { GenerateCertificateDto } from './dto/generate-certificate.dto';
import { CertificateService } from './certificate.service';

@Controller('certificate')
@ApiTags('certificate')
export class CertificateController {
  constructor(private readonly certificateService: CertificateService) {}
  @Post('create')
  async createCertificate(@Body() body: GenerateCertificateDto) {
    return this.certificateService.generateCertificate(body);
  }
}
