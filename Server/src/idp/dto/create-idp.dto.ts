import {
  IsBoolean,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';
import { MessageSigningOrderEnum } from '../enums/message-signing-order.enum';

import { ApiProperty } from '@nestjs/swagger';
import { GenerateId } from 'src/utils';
import { NameIDFormatEnum } from '../enums/name-id.enum';

export class CreateIdpDto {
  @IsString()
  @IsOptional()
  @ApiProperty({
    default: GenerateId('idp', 17),
  })
  idpId: string;

  //  @IsUrl()
  @IsNotEmpty()
  entityID: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: NameIDFormatEnum.emailAddress,
    enum: NameIDFormatEnum,
  })
  nameIdFormat: NameIDFormatEnum;

  //  @IsUrl()
  @IsNotEmpty()
  ssoUrl: string;

  @IsString()
  //  @IsUrl()
  @IsOptional()
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
}
