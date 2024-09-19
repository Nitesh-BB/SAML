import * as joi from 'joi';

const nodeEnvSchema = joi
  .string()
  .valid('development', 'production')
  .default('development');

export const configValidationSchema = joi.object({
  NODE_ENV: nodeEnvSchema,
  PORT: joi.number().default(4000),
  MONGO_URI: joi.string().required(),
  SESSION_SECRET: joi.string().required(),
  SERVER_URL: joi.string().when('NODE_ENV', {
    is: 'production',
    then: joi.required(),
    otherwise: joi.string().default('http://localhost:4000'),
  }),
});

export const configValidationOptions = {
  allowUnknown: true,
};
