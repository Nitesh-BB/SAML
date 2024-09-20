import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { v4 as uuid } from 'uuid';

export class CreateServiceProviderDto {
  @IsOptional()
  @IsString()
  @ApiProperty({
    example: uuid(),
  })
  spId: string;

  @IsString()
  @IsNotEmpty()
  idpId: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    example: 'https://sp.com/acs',
  })
  entityID: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    example: 'https://sp.com/acs',
  })
  acsUrl: string;

  @IsOptional()
  @IsString()
  @ApiProperty({
    example: 'https://sp.com/slo',
  })
  sloUrl: string;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    default: false,
  })
  wantMessageSigned: boolean;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    default: false,
  })
  authnRequestsSigned: boolean;

  @IsOptional()
  @IsString()
  signingCert: string;

  @IsOptional()
  @IsString()
  encryptCert: string;
}
