import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class UpdateServiceProviderDto {
  @IsOptional()
  @IsString()
  acsUrl?: string;

  @IsOptional()
  @IsBoolean()
  wantMessageSigned?: boolean;

  @IsOptional()
  @IsBoolean()
  authnRequestsSigned?: boolean;

  @IsOptional()
  @IsString()
  signingCert?: string;

  @IsOptional()
  @IsString()
  encryptCert?: string;
}
