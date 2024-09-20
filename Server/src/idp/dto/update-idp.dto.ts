import { IsBoolean, IsEnum, IsOptional, IsString } from 'class-validator';

import { MessageSigningOrderEnum } from '../enums/message-signing-order.enum';

import { ApiProperty, PartialType } from '@nestjs/swagger';
import { NameIDFormatEnum } from '../enums/name-id.enum';
import { CreateIdpDto } from './create-idp.dto';
import { Exclude } from 'class-transformer';

export class UpdateIdpDto extends PartialType(CreateIdpDto) {
  @Exclude()
  idpId: string;

  @IsString()
  @IsOptional()
  @ApiProperty({
    default: NameIDFormatEnum.emailAddress,
    enum: NameIDFormatEnum,
  })
  nameIdFormat: NameIDFormatEnum;

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

  @IsBoolean()
  @IsOptional()
  wantAuthnRequestsSigned: boolean;

  @IsBoolean()
  @IsOptional()
  isAssertionEncrypted: boolean;
}
