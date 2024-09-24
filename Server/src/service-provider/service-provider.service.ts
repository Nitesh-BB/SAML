import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import * as samlify from 'samlify';
import { GenerateId } from 'src/utils';
import { CreateServiceProviderDto } from './dto/create-service-provider.dto';
import { UpdateServiceProviderDto } from './dto/update-service-provider.dto';
import {
  ServiceProvider,
  ServiceProviderDocument,
} from './entities/service-provider.entity';

@Injectable()
export class ServiceProviderService {
  private readonly logger = new Logger('ServiceProviderService');
  constructor(
    @InjectModel(ServiceProvider.name)
    private readonly serviceProviderModel: mongoose.Model<ServiceProviderDocument>,
  ) {}

  async createSp(body: CreateServiceProviderDto) {
    try {
      this.logger.log('Creating Service Provider');
      body.spId = body.spId || GenerateId('sp', 18);
      return await this.serviceProviderModel.create(body);
    } catch (error) {
      this.logger.error('Error in createSp: ' + error);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async updateSp(idpId: string, body: UpdateServiceProviderDto) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        $or: [{ entityID: idpId }, { spId: idpId }],
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      const updatedSp = await this.serviceProviderModel.findOneAndUpdate(
        { $or: [{ entityID: idpId }, { spId: idpId }] },
        body,
        { new: true },
      );

      return updatedSp;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
  async getMetaData(spId: string) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        $or: [{ entityID: spId }, { spId }],
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      const spInstance = samlify.ServiceProvider({
        entityID: sp.entityID,
        assertionConsumerService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.acsUrl,
          },
        ],
        wantAssertionsSigned: sp.wantAssertionsSigned,
        wantMessageSigned: sp.wantMessageSigned,
        authnRequestsSigned: sp.authnRequestsSigned,

        signingCert: sp.signingCert,
        encryptCert: sp.encryptCert,
        singleLogoutService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.sloUrl || 'http://localhost:5000/sp/slo',
          },
        ],
      });
      const spMetadata = spInstance.getMetadata();

      return spMetadata;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getSpMetadataByEntityId(entityId: string, idpId: string) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        entityID: entityId,
        idpId,
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      const spMetaData = samlify.ServiceProvider({
        entityID: sp.entityID,
        assertionConsumerService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.acsUrl,
          },
        ],
        wantMessageSigned: sp.wantMessageSigned,
        authnRequestsSigned: sp.authnRequestsSigned,
        signingCert: sp.signingCert,
        singleLogoutService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.sloUrl || 'http://localhost:5000/sp/slo',
          },
        ],
      });
      return spMetaData.getMetadata();
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getSp(spId: string) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        $or: [{ entityID: spId }, { spId: spId }],
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      return sp;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getSpUsingIssuer(entityID: string, idpId: string) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        entityID,
        idpId,
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      return sp;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
  async getAllSp(idpId: string) {
    try {
      return await this.serviceProviderModel.find({
        idpId,
      });
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async deleteSp(id: string) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        $or: [{ entityID: id }, { spId: id }],
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      return await this.serviceProviderModel.findOneAndDelete({
        $or: [{ entityID: id }, { spId: id }],
      });
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getSpInstance(entityId: string, idpId: string, idpData: any) {
    try {
      const sp = await this.serviceProviderModel.findOne({
        entityID: entityId,
        idpId,
      });

      if (!sp) {
        throw new HttpException('Service Provider not found', 404);
      }

      const spInstance = samlify.ServiceProvider({
        entityID: sp.entityID,
        assertionConsumerService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.acsUrl,
          },
        ],
        isAssertionEncrypted: idpData.isAssertionEncrypted,
        wantAssertionsSigned: sp.wantAssertionsSigned,
        wantMessageSigned: sp.wantMessageSigned,
        authnRequestsSigned: sp.authnRequestsSigned,
        nameIDFormat: [idpData.nameIDFormat],
        transformationAlgorithms: [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#',
        ],

        signingCert: sp.signingCert,
        encryptCert: sp.encryptCert,
        singleLogoutService: [
          {
            Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            Location: sp.sloUrl || 'http://localhost:5000/sp/slo',
          },
        ],
      });

      return spInstance;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
}
