import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';

interface sessionInterface {
  idpId: string;
  requestId: string;
  authenticator: string;
  relayState: string;
  issuer: string;
}

@Schema({
  _id: false,
})
export class Session {
  _id: string;

  @Prop({ type: Object })
  session: sessionInterface;

  @Prop({ type: Object })
  user: any;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
