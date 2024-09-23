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
    example:
      'http://localhost:8080/sp/entity/6e5400ce-cef4-4a24-89ad-42f304369df5',
  })
  entityID: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    example: 'http://localhost:8080/sp/acs',
  })
  acsUrl: string;

  @IsOptional()
  @IsString()
  @ApiProperty({
    example: 'http://localhost:8080/sp/slo',
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

  @IsOptional()
  @IsBoolean()
  @ApiProperty({
    default: false,
  })
  wantAssertionsSigned: boolean;
}
