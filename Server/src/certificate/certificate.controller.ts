import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { GenerateCertficateDto } from './dto/generate-certficate.dto';
import { CertificateService } from './certificate.service';

@Controller('certificate')
@ApiTags('certificate')
export class CertificateController {
  constructor(private readonly certificateService: CertificateService) {}
  @Post('create')
  async createCertificate(@Body() body: GenerateCertficateDto) {
    return this.certificateService.generateSelfSignedCertificate(body);
  }
}
