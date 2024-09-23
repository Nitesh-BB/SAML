import * as validator from '@authenio/samlify-xsd-schema-validator';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import * as samlify from 'samlify';
import { CertificateService } from 'src/certificate/certificate.service';
import { GenerateCertificateDto } from 'src/certificate/dto/generate-certificate.dto';
import { ServiceProviderService } from 'src/service-provider/service-provider.service';
import * as fs from 'fs';
import { GenerateId } from 'src/utils';
import * as uuid from 'uuid';
import { CreateIdpDto } from './dto/create-idp.dto';
import { UpdateIdpDto } from './dto/update-idp.dto';
import { Idp, IdpDocument } from './entities/idp.entity';
import { MessageSigningOrderEnum } from './enums/message-signing-order.enum';
import { NameIDFormatEnum } from './enums/name-id.enum';
import * as path from 'path';
import { ConfigService } from '@nestjs/config';
import { max } from 'class-validator';
import { IdpMetadata } from 'samlify/types/src/metadata-idp';
samlify.setSchemaValidator(validator);

interface User {
  email: string;
  firstName: string;
  lastName: string;
  userId: string;
}

const loginResponseTemplate = ({ attributes }: { attributes: any }) => {
  const templatePath = path.join(__dirname, './templates/login-response.xml');
  return {
    context: fs.readFileSync(templatePath, 'utf-8'),
    attributes,
    additionalTemplates: {},
  };
};

@Injectable()
export class IdpService {
  constructor(
    @InjectModel(Idp.name)
    private readonly idpModel: mongoose.Model<IdpDocument>,

    @InjectModel('sessions')
    private readonly sessionModel: mongoose.Model<any>,
    private readonly serviceProviderService: ServiceProviderService,
    private readonly certificateService: CertificateService,
    private readonly configService: ConfigService,
  ) {}

  private readonly logger = new Logger('IdpService');
  private readonly serverUrl = process.env.SERVER_URL;

  async createIdp(createIdpDto: CreateIdpDto) {
    try {
      const idpId = createIdpDto.idpId || GenerateId('idp', 17);

      const idp = await this.idpModel.findOne({
        idpId,
      });

      if (idp) {
        throw new HttpException(
          'Idp with given id already exists',
          HttpStatus.BAD_REQUEST,
        );
      }

      const serverUrl = new URL(this.configService.get('server.url'));

      const idpEntityId = `${serverUrl.origin}/entity/${idpId}`;

      const generateCertificateDto = new GenerateCertificateDto({
        commonName: idpId,
        countryName: 'IN',
        state: 'MH',
        locality: 'Pune',
        organization: 'Blue-bricks',
        organizationUnit: 'SAML-IDP',
        validDays: 3650,
        sigalg: 'SHA256withRSA',
      });

      const signingCert = this.certificateService.generateCertificate(
        generateCertificateDto,
      );
      const encryptionCert = this.certificateService.generateCertificate(
        generateCertificateDto,
      );

      const newIdp = await this.idpModel.create({
        ...createIdpDto,
        idpId,
        signingCert: signingCert.certificate,
        encryptCert: encryptionCert.certificate,
        privateKey: signingCert.privateKey,
        encPrivateKey: encryptionCert.privateKey,
        entityID: idpEntityId,
      });

      this.logger.log(`Idp ${createIdpDto.idpId} created`);
      return newIdp;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async updateIdp(idpId: string, updateIdpDto: UpdateIdpDto) {
    try {
      this.logger.log(`Updating Idp ${idpId}`);

      let idp = await this.idpModel.findOne({
        idpId,
      });
      if (!idp) {
        throw new HttpException('Idp not found', HttpStatus.BAD_REQUEST);
      }

      Object.keys(updateIdpDto).forEach((key) => {
        idp[key] = updateIdpDto[key];
      });

      idp = await idp.save();

      this.logger.log(`Idp ${idpId} updated`);
      return idp;
    } catch (error) {
      this.logger.error(error.message);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getIdp(idpId: string) {
    try {
      const idp = await this.idpModel.findOne({
        $or: [{ idpId: idpId }, { entityID: idpId }],
      });

      if (!idp) throw new HttpException('Idp not found', HttpStatus.NOT_FOUND);
      return idp;
    } catch (error) {
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async getMetaData(idpId: string) {
    try {
      const idp = await this.idpModel.findOne({
        $or: [{ entityID: idpId }, { idpId: idpId }],
      });

      if (!idp) {
        throw new HttpException(
          'No IDP found with given Id',
          HttpStatus.NOT_FOUND,
        );
      }

      const singleSignOnService = [
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          Location: `${this.serverUrl}/idp/login/${idpId}`,
        },
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          Location: `${this.serverUrl}/idp/login/${idpId}`,
        },
      ];

      const singleLogoutService = [
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
          Location: `${this.serverUrl}/idp/logout/${idpId}`,
        },
        {
          Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          Location: `${this.serverUrl}/idp/logout/${idpId}`,
        },
      ];
      const IdpInstance = samlify.IdentityProvider({
        entityID: idp.entityID,
        wantAuthnRequestsSigned: idp.wantAuthnRequestsSigned,
        signingCert: idp.signingCert,
        encryptCert: idp.encryptCert,
        privateKey: idp.privateKey,
        encPrivateKey: idp.encPrivateKey,
        singleLogoutService,
        singleSignOnService,
        isAssertionEncrypted: idp.isAssertionEncrypted,
        messageSigningOrder: idp.messageSigningOrder,
        loginResponseTemplate: loginResponseTemplate({
          attributes: idp.attributes,
        }),
        nameIDFormat: [idp.nameIdFormat || NameIDFormatEnum.unspecified],
      });

      return IdpInstance.getMetadata();
    } catch (error) {
      this.logger.error(error.message);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async loginPost(req: any, res: any, binding = 'post', idpId: string) {
    try {
      // Check for session cookie first

      const forceLogin = req.query?.forceLogin === 'true' ? true : false;

      const sessionCookie = req.cookies?.sessionIndex;

      if (sessionCookie && !forceLogin) {
        this.logger.log(`Session cookie found. Sending direct login response.`);

        const userSession = await this.sessionModel.findOne({
          _id: sessionCookie,
        });

        if (userSession && userSession.session && userSession.user) {
          const { session } = userSession;

          const { issuer, relayState = '' } = session;
          const [idpData, spMetaData] = await Promise.all([
            this.getIdp(idpId),
            this.serviceProviderService.getSpMetadataByEntityId(issuer, idpId),
          ]);
          console.log(`constructed idp and sp metadata`);
          // Initialize SP and IdP
          const sp = samlify.ServiceProvider({
            metadata: spMetaData,
          });
          const idpMetaData = await this.getMetaData(idpId);
          const idp = this.getIdpInstance(idpMetaData, idpData);

          console.log(`fetched sp and idp metadata`);

          const result = await idp.createLoginResponse(
            sp,
            {
              extract: {
                request: {
                  id: userSession.session.requestId,
                },
              },
            },
            'post',
            userSession.user,
            this.createTemplateCallback(
              idp,
              sp,
              'post',
              userSession.user,
              userSession.session.requestId,
              userSession,
            ),
            idpData.messageSigningOrder ===
              MessageSigningOrderEnum.ENCRYPT_THEN_SIGN,
            relayState || idpData.defaultRelayState,
          );

          return res.render('sp-post', result);
        }
      }

      // No session cookie, proceed with normal SAML processing
      let SAMLRequest: string, decodedString: string, relayState: string;

      if (binding === 'post') {
        SAMLRequest = req.body.SAMLRequest;
        relayState = req.body.RelayState;
      } else {
        SAMLRequest = req.query.SAMLRequest;
        relayState = req.query.RelayState;
      }

      decodedString =
        binding === 'post'
          ? Buffer.from(SAMLRequest, 'base64').toString('ascii')
          : samlify.Utility.inflateString(decodeURIComponent(SAMLRequest));

      const { issuer } = samlify.Extractor.extract(decodedString, [
        {
          key: 'issuer',
          localPath: ['AuthnRequest', 'Issuer'],
          attributes: [],
        },
      ]);

      this.logger.log(`SAML Request From EntityId : ${issuer}`);

      const idpData = await this.getIdp(idpId);
      const idpMetadata = await this.getMetaData(idpId);
      const idp = this.getIdpInstance(idpMetadata, idpData);

      const spMetadata =
        await this.serviceProviderService.getSpMetadataByEntityId(
          issuer,
          idpId,
        );
      const sp = samlify.ServiceProvider({
        metadata: spMetadata,
      });

      const { extract } = await idp.parseLoginRequest(sp, binding, req);

      this.logger.log(`Creating Session for EntityId ${issuer}`);

      // Set session information
      req.session.requestId = extract.request.id;
      req.session.authenticator = idpData.entityID;
      req.session.relayState = relayState;
      req.session.issuer = issuer;
      req.session.idpId = idpId;

      req.session.cookie.maxAge = idpData.sessionTTl || 24 * 60 * 60 * 1000;

      res.cookie('sessionIndex', req.session.id, {
        httpOnly: true,
        secure: true,
        maxAge: idpData.sessionTTl || 24 * 60 * 60 * 1000,
      });

      return res.redirect(
        `${idpData.ssoUrl}?requestId=${extract.request.id}&idpId=${idpId}`,
      );
    } catch (error) {
      this.logger.error(`Error in loginPost: ${error.message}`);
      throw new HttpException(
        `Failed to process SAML request: ${error.message}`,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async loginRedirect(req: any, res: any, idpId: string) {
    try {
      req.octetString = this.buildOctetStringFromQuery(req.query);
      return this.loginPost(req, res, 'redirect', idpId);
    } catch (error) {
      this.logger.error(`Error in loginRedirect: ${error.message}`);
      throw new HttpException(
        `Failed to handle SAML redirect: ${error.message}`,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  private getIdpInstance(metadata: any, idp: Idp) {
    return samlify.IdentityProvider({
      messageSigningOrder: idp.messageSigningOrder,
      isAssertionEncrypted: idp.isAssertionEncrypted,
      metadata,
      privateKey: idp.privateKey,
      encPrivateKey: idp.encPrivateKey,
      loginResponseTemplate: loginResponseTemplate({
        attributes: idp.attributes,
      }),
    });
  }

  async createSession(req: any, res: any) {
    try {
      this.logger.log('Creating Session');

      const { requestId } = req.query;
      if (!requestId) {
        throw new HttpException(
          'Invalid Request, No Request Id Found',
          HttpStatus.BAD_REQUEST,
        );
      }

      if (!req.body)
        throw new HttpException(
          'Invalid Request, No User Data Found in Request',
          HttpStatus.BAD_REQUEST,
        );

      if (!req.body.nameID && !req.body.email) {
        throw new HttpException(
          'Invalid Request, nameID or email is required',
          HttpStatus.BAD_REQUEST,
        );
      }

      const savedSession = await this.sessionModel.findOne({
        'session.requestId': requestId,
      });

      if (!savedSession || !savedSession.session) {
        throw new HttpException(
          'Invalid Session, Please Try Again',
          HttpStatus.BAD_REQUEST,
        );
      }

      const { session } = savedSession;

      const { idpId, issuer, relayState = '' } = session;

      // Fetch IdP data
      const [idpData, spMetaData] = await Promise.all([
        this.getIdp(idpId),
        this.serviceProviderService.getSpMetadataByEntityId(issuer, idpId),
      ]);

      // Initialize SP and IdP
      const sp = samlify.ServiceProvider({
        metadata: spMetaData,
      });
      const idpMetaData = await this.getMetaData(idpId);
      const idp = this.getIdpInstance(idpMetaData, idpData);

      // Create user login response for SP
      const info = { extract: { request: { id: requestId } } };
      const user = req.body;
      const result = await idp.createLoginResponse(
        sp,
        info,
        'post',
        user,
        this.createTemplateCallback(
          idp,
          sp,
          'post',
          user,
          requestId,
          savedSession,
        ),
        idpData.messageSigningOrder ===
          MessageSigningOrderEnum.ENCRYPT_THEN_SIGN,
        relayState || idpData.defaultRelayState,
      );

      // Update and save session with user data
      savedSession.user = user;
      await savedSession.save();

      this.logger.log('Login Response created, redirecting to SP');
      return res.render('sp-post', result);
    } catch (error) {
      this.logger.error('Error in creating session', error.message);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  // Utility function to set session in cookie

  async logoutPost(req: any, res: any, binding: string, idpId: string) {
    try {
      console.log('Logout Request Received', { binding, idpId });
      let SAMLRequest: string, decodedString: string, relayState: string;

      if (binding === 'post') {
        SAMLRequest = req.body.SAMLRequest;
        decodedString = Buffer.from(SAMLRequest, 'base64').toString('ascii');
        relayState = req.body.RelayState;
      } else {
        SAMLRequest = req.query.SAMLRequest;
        relayState = req.query.RelayState;
        decodedString = samlify.Utility.inflateString(
          decodeURIComponent(SAMLRequest),
        );
      }

      const { issuer } = samlify.Extractor.extract(decodedString, [
        {
          key: 'issuer',
          localPath: ['LogoutRequest', 'Issuer'],
          attributes: [],
        },
      ]);

      if (!issuer) {
        throw new HttpException(
          'Invalid Request,No Issuer Found in Request',
          HttpStatus.BAD_REQUEST,
        );
      }

      this.logger.log(`SAML Request From EntityId : ${issuer}`);

      const idpData = await this.getIdp(idpId);
      const idpMetadata = await this.getMetaData(idpId);
      const idp = samlify.IdentityProvider({
        metadata: idpMetadata,
        privateKey: idpData.privateKey,
        encPrivateKey: idpData.encPrivateKey,
        messageSigningOrder: idpData.messageSigningOrder,
      });

      const spmetadata =
        await this.serviceProviderService.getSpMetadataByEntityId(
          issuer,
          idpId,
        );

      const sp = samlify.ServiceProvider({
        metadata: spmetadata,
      });

      const { extract } = await idp.parseLogoutRequest(sp, binding, req);

      const result = idp.createLogoutResponse(
        sp,
        { extract: { request: { id: extract.request.id } } },
        binding,
        relayState,
      );

      const sessionCookie = req.cookies?.sessionIndex;

      if (sessionCookie) {
        await this.sessionModel.deleteOne({ _id: sessionCookie });

        res.clearCookie('sessionIndex');
      }

      return res.render('sp-post', result);
    } catch (error) {
      this.logger.error(error.message);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
  async logoutRedirect(req: any, res: any, idpId: string) {
    req.octetString = this.buildOctetStringFromQuery(req.query);
    return this.logoutPost(req, res, 'redirect', idpId);
  }

  buildOctetStringFromQuery(query: any): string {
    return Object.keys(query)
      .filter((param) => param !== 'Signature')
      .map((param) => param + '=' + encodeURIComponent(query[param]))
      .join('&');
  }

  createTemplateCallback =
    (
      _idp: any,
      _sp: any,
      _binding: string,
      user: any,
      requestId: string,
      savedSession: any,
    ) =>
    (template) => {
      const now = new Date();
      const spEntityID = _sp.entityMeta.getEntityID();
      const idpSetting = _idp.entitySetting;

      const sessionExpiresIn = savedSession?.expires
        ? new Date(savedSession.expires)
        : new Date(Date.now() + 24 * 60 * 60 * 1000);

      const sessionIndex = savedSession?._id || uuid.v4();
      const tvalue = {
        ID: requestId,
        AssertionID: idpSetting.generateID
          ? idpSetting.generateID()
          : `${uuid.v4()}`,
        Destination: _sp.entityMeta.getAssertionConsumerService(_binding),
        Audience: spEntityID,
        SubjectRecipient: _sp.entityMeta.getAssertionConsumerService(_binding),
        NameIDFormat: _idp.entitySetting.nameIDFormat,
        NameID: user.nameID || user.email,
        Issuer: _idp.entityMeta.getEntityID(),
        IssueInstant: now.toISOString(),
        ConditionsNotBefore: now.toISOString(),
        ConditionsNotOnOrAfter: sessionExpiresIn.toISOString(),
        SubjectConfirmationDataNotOnOrAfter: sessionExpiresIn.toISOString(),
        AssertionConsumerServiceURL:
          _sp.entityMeta.getAssertionConsumerService(_binding),
        EntityID: spEntityID,
        InResponseTo: requestId,
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',

        AuthnStatement: `
                <saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionNotOnOrAfter="${sessionExpiresIn.toISOString()}" SessionIndex="${sessionIndex}">
                    <saml:AuthnContext>
                        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                    </saml:AuthnContext>
                </saml:AuthnStatement>
                `,
      };

      if (user) {
        Object.keys(user).forEach((key) => {
          const value = user[key];

          const attrName = `attrUser${key.charAt(0).toUpperCase() + key.slice(1)}`;

          tvalue[attrName] = value;
        });
      }

      return {
        id: requestId,
        context: samlify.SamlLib.replaceTagsByValue(template, tvalue),
      };
    };

  async deleteIdp(idpId: string) {
    try {
      const idp = await this.getIdp(idpId);
      if (!idp) {
        throw new HttpException(
          'Invalid Request,No Idp Found',
          HttpStatus.BAD_REQUEST,
        );
      }

      await this.idpModel.deleteOne({ idpId });

      await this.sessionModel.deleteMany({ 'session.idpId': idpId });
      return {
        message: 'Idp Deleted Successfully',
      };
    } catch (error) {
      this.logger.error(error.message);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
}
