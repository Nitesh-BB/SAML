import { PartialType } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString } from 'class-validator';
import { CreateIdpDto } from 'src/idp/dto/create-idp.dto';
import { CreateServiceProviderDto } from './create-service-provider.dto';
import { Exclude } from 'class-transformer';

export class UpdateServiceProviderDto extends PartialType(
  CreateServiceProviderDto,
) {
  @Exclude()
  idpId: string;

  @Exclude()
  spId: string;
}
