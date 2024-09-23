import {
  IsBoolean,
  IsDefined,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';
import { MessageSigningOrderEnum } from '../enums/message-signing-order.enum';

import { ApiProperty } from '@nestjs/swagger';
import { v4 as uuid } from 'uuid';
import { NameIDFormatEnum } from '../enums/name-id.enum';
import { Type } from 'class-transformer';
import { AttributeNameFormat } from '../enums/attributes-nameformat.enum';
import { AttributesValueType } from '../enums/attributes-value-type.enum';

export class CreateIdpDto {
  @IsString()
  @IsOptional()
  @ApiProperty({
    default: uuid(),
  })
  idpId: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: NameIDFormatEnum.emailAddress,
    enum: NameIDFormatEnum,
  })
  nameIdFormat: NameIDFormatEnum;

  @ApiProperty({
    example: 'http://localhost:4000/login',
  })
  @IsNotEmpty()
  ssoUrl: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    example: 'http://localhost:4000/logout',
  })
  sloUrl: string;

  @IsBoolean()
  @IsOptional()
  @ApiProperty({
    default: false,
  })
  wantAuthnRequestsSigned: boolean;

  @IsBoolean()
  @IsOptional()
  @ApiProperty({
    default: false,
  })
  isAssertionEncrypted: boolean;

  @IsEnum(MessageSigningOrderEnum)
  @IsOptional()
  @ApiProperty({
    default: MessageSigningOrderEnum.SIGN_THEN_ENCRYPT,
    enum: MessageSigningOrderEnum,
  })
  messageSigningOrder: string;

  @IsString()
  @IsOptional()
  defaultRelayState: string;

  @IsDefined()
  @Type(() => AttributesDto)
  @ValidateNested({ each: true })
  attributes: AttributesDto[];

  @IsOptional()
  @IsNumber()
  @ApiProperty({
    example: 7 * 24 * 60 * 60 * 1000,
    default: 7 * 24 * 60 * 60 * 1000,
    description: 'Session Time to Live in milliseconds',
  })
  sessionTTl: number;
}

export class AttributesDto {
  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    example: 'id',
  })
  name: string;

  @IsNotEmpty()
  @IsString()
  @ApiProperty({
    example: 'user.id',
  })
  valueTag: string;

  @IsNotEmpty()
  @IsString()
  @IsEnum(AttributeNameFormat)
  @ApiProperty({
    example: AttributeNameFormat.BASIC,
    enum: AttributeNameFormat,
    default: AttributeNameFormat.BASIC,
  })
  nameFormat: string;

  @IsNotEmpty()
  @IsString()
  @IsEnum(AttributesValueType)
  @ApiProperty({
    example: AttributesValueType.STRING,
    enum: AttributesValueType,
    default: AttributesValueType.STRING,
  })
  valueXsiType: string;
}
