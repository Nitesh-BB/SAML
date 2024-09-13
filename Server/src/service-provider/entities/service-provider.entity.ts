import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import { GenerateId } from 'src/utils';

export type ServiceProviderDocument = mongoose.Document & ServiceProvider;
@Schema()
export class ServiceProvider {
  @Prop({ unique: true, default: GenerateId('sp', 18) })
  spId: string;

  @Prop({ required: true })
  idpId: string;

  @Prop({ type: String, required: true })
  entityID: string;

  @Prop()
  wantMessageSigned: boolean;

  @Prop()
  authnRequestsSigned: boolean;

  @Prop()
  signingCert: string;

  @Prop()
  encryptCert: string;

  @Prop({ type: String, required: true })
  acsUrl: string;

  @Prop({ type: String, required: false })
  sloUrl: string;
}

export const ServiceProviderSchema =
  SchemaFactory.createForClass(ServiceProvider);
