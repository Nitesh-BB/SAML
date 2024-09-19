import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsEnum,
} from 'class-validator';

export class GenerateCertificateDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    default: 'IN',
  })
  countryName: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    default: 'Maharashtra',
  })
  state: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: 'Pune',
  })
  locality: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    default: 'blue-bricks',
  })
  organization: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: 'Developer',
  })
  organizationUnit: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    default: 'https://blue-bricks.com',
  })
  commonName: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: '',
  })
  emailAddress?: string;

  @IsNumber()
  @IsOptional()
  @ApiProperty({
    default: 365,
  })
  validDays: number;

  @IsEnum(['SHA256withRSA', 'SHA512withRSA'])
  @ApiProperty({
    enum: ['SHA256withRSA', 'SHA512withRSA'],
    default: 'SHA256withRSA',
  })
  @IsOptional()
  sigalg: string;

  constructor(partial: GenerateCertificateDto) {
    Object.assign(this, partial);
  }
}
