import { Schema, SchemaFactory, Prop } from '@nestjs/mongoose';
import { Document } from 'mongoose';

// Define session interface for better structure
export interface SessionInterface {
  idpId: string;
  requestId: string;
  authenticator: string;
  relayState?: string; // Optional, depending on usage
  issuer: string;
}

// Define a user interface or schema for better type safety (optional)
export interface UserInterface {
  email: string;
  name?: string;
  [key: string]: any; // Allow additional dynamic fields
}

@Schema({ _id: false })
export class Session extends Document {
  _id: string;

  @Prop({ type: String, required: true })
  idpId: string;

  @Prop({ type: String, required: true })
  requestId: string;

  @Prop({ type: String, required: true })
  authenticator: string;

  @Prop({ type: String, default: '' })
  relayState?: string;

  @Prop({ type: String, required: true })
  issuer: string;

  @Prop({ type: Object })
  user: UserInterface;
}

// Create schema
export const SessionSchema = SchemaFactory.createForClass(Session);
