import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class CreateServiceProviderDto {
  @IsOptional()
  @IsString()
  spId: string;

  @IsString()
  @IsNotEmpty()
  idpId: string;

  @IsNotEmpty()
  @IsString()
  entityID: string;

  @IsNotEmpty()
  @IsString()
  acsUrl: string;

  @IsOptional()
  @IsString()
  sloUrl: string;

  @IsOptional()
  @IsBoolean()
  wantMessageSigned: boolean;

  @IsOptional()
  @IsBoolean()
  authnRequestsSigned: boolean;

  @IsOptional()
  @IsString()
  signingCert: string;

  @IsOptional()
  @IsString()
  encryptCert: string;
}
