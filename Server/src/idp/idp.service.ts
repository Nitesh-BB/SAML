import * as validator from '@authenio/samlify-xsd-schema-validator';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as mongoose from 'mongoose';
import * as samlify from 'samlify';
import { CertificateService } from 'src/certificate/certificate.service';
import { GenerateCertficateDto } from 'src/certificate/dto/generate-certficate.dto';
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
samlify.setSchemaValidator(validator);

interface User {
  email: string;
  firstName: string;
  lastName: string;
  userId: string;
}
@Injectable()
export class IdpService {
  constructor(
    @InjectModel(Idp.name)
    private readonly idpModel: mongoose.Model<IdpDocument>,

    @InjectModel('sessions')
    private readonly sessionModel: mongoose.Model<any>,
    private readonly serviceProviderService: ServiceProviderService,
    private readonly certificateService: CertificateService,
  ) {}

  private readonly logger = new Logger('IdpService');
  private readonly serverUrl = process.env.SERVER_URL;

  templatePath = path.join(__dirname, './templates/login-response.xml');

  loginResponseTemplate = {
    context: fs.readFileSync(this.templatePath, 'utf-8'),
    attributes: [
      {
        name: 'mail',
        valueTag: 'user.email',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueXsiType: 'xs:string',
      },
      {
        name: 'userId',
        valueTag: 'user.id',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueXsiType: 'xs:string',
      },

      {
        name: 'firstname',
        valueTag: 'user.firstName',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueXsiType: 'xs:string',
      },
      {
        name: 'lastname',
        valueTag: 'user.lastName',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        valueXsiType: 'xs:string',
      },
    ],
    additionalTemplates: {},
  };

  async createIdp(createIdpDto: CreateIdpDto) {
    try {
      this.logger.log(`Creating Idp ${createIdpDto.entityID}`);
      const idp = await this.idpModel.findOne({
        entityID: createIdpDto.entityID,
      });
      if (idp) {
        throw new HttpException('Idp already exists', HttpStatus.BAD_REQUEST);
      }

      const idpId = createIdpDto.idpId || GenerateId('idp', 17);

      const generateCertficateDto = new GenerateCertficateDto();
      generateCertficateDto.commonName = idpId;
      generateCertficateDto.countryName = 'IN';
      generateCertficateDto.state = 'MH';
      generateCertficateDto.locality = 'Pune';
      generateCertficateDto.organization = 'Passwordless4u';
      generateCertficateDto.organizationUnit = 'SAML-IDP';
      generateCertficateDto.validDays = 3650;

      const signingCert = await this.certificateService.generateCertificate(
        generateCertficateDto,
      );
      const encryptionCert = await this.certificateService.generateCertificate(
        generateCertficateDto,
      );

      const newIdp = await this.idpModel.create({
        ...createIdpDto,
        idpId,
        signingCert: signingCert.certificate,
        encryptCert: encryptionCert.certificate,
        privateKey: signingCert.privateKey,
        encPrivateKey: encryptionCert.privateKey,
      });

      this.logger.log(`Idp ${createIdpDto.entityID} created`);
      return newIdp;
    } catch (error) {
      this.logger.error(error);
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

      if (updateIdpDto.hasOwnProperty('isAssertionEncrypted'))
        idp.isAssertionEncrypted = updateIdpDto.isAssertionEncrypted;
      if (updateIdpDto.hasOwnProperty('wantAuthnRequestsSigned'))
        idp.wantAuthnRequestsSigned = updateIdpDto.wantAuthnRequestsSigned;
      if (updateIdpDto.hasOwnProperty('defaultRelayState'))
        idp.defaultRelayState = updateIdpDto.defaultRelayState;
      if (updateIdpDto.hasOwnProperty('nameIdFormat'))
        idp.nameIdFormat = updateIdpDto.nameIdFormat;
      if (updateIdpDto.hasOwnProperty('messageSigningOrder'))
        idp.messageSigningOrder = updateIdpDto.messageSigningOrder;
      idp = await idp.save();

      this.logger.log(`Idp ${idpId} updated`);
      return idp;
    } catch (error) {
      this.logger.error(error);
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
          'No IDP found with geiven Id',
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
        //singleLogoutService,
        singleSignOnService,
        isAssertionEncrypted: idp.isAssertionEncrypted,
        messageSigningOrder: idp.messageSigningOrder,
        loginResponseTemplate: this.loginResponseTemplate,
        nameIDFormat: [idp.nameIdFormat || NameIDFormatEnum.unspecified],
      });

      return IdpInstance.getMetadata();
    } catch (error) {
      this.logger.error(error);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async loginPost(req: any, res: any, binding = 'post', idpId: string) {
    try {
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
          localPath: ['AuthnRequest', 'Issuer'],
          attributes: [],
        },
      ]);

      this.logger.log(`SAML Request From EntittyId : ${issuer}`);

      const idpData = await this.getIdp(idpId);
      const idpMetadata = await this.getMetaData(idpId);
      const idp = samlify.IdentityProvider({
        metadata: idpMetadata,
        privateKey: idpData.privateKey,
        encPrivateKey: idpData.encPrivateKey,
        messageSigningOrder: idpData.messageSigningOrder,
        loginResponseTemplate: this.loginResponseTemplate,
      });

      const spmetadata =
        await this.serviceProviderService.getSpMetadataByEntityId(
          issuer,
          idpId,
        );

      const sp = samlify.ServiceProvider({
        metadata: spmetadata,
      });

      const { extract } = await idp.parseLoginRequest(sp, binding, req);

      this.logger.log(`Creating Session for EntityId ${issuer}`);

      req.session.requestId = extract.request.id;
      req.session.authenticator = idpData.entityID;
      req.session.relayState = relayState;
      req.session.issuer = issuer;
      req.session.idpId = idpId;
      //req.session.user = null;
      return res.redirect(
        `${idpData.ssoUrl}?requestId=${extract.request.id}&idpId=${idpId}`,
      );
    } catch (error) {
      this.logger.error(error);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async createSession(req: any, res: any) {
    try {
      this.logger.log(`Creating Session `);
      const { requestId } = req.query;

      if (!requestId) {
        throw new HttpException(
          'Invalid Session,Please Try Again',
          HttpStatus.BAD_REQUEST,
        );
      }

      const savedSession = await this.sessionModel.findOne({
        'session.requestId': requestId,
      });

      if (!savedSession) {
        throw new HttpException(
          'Invalid Session,Please Try Again',
          HttpStatus.BAD_REQUEST,
        );
      }

      const { session } = savedSession;
      const { idpId } = session;
      this.logger.log(
        `Got Session for requestId ${requestId} JSON ${JSON.stringify(
          session,
        )}`,
      );
      const idpData = await this.getIdp(idpId);

      const spMetaData =
        await this.serviceProviderService.getSpMetadataByEntityId(
          session.issuer,
          session.idpId,
        );
      const sp = samlify.ServiceProvider({
        metadata: spMetaData,
      });

      const idpMetaData = await this.getMetaData(idpId);
      const idp = samlify.IdentityProvider({
        metadata: idpMetaData,
        privateKey: idpData.privateKey,
        encPrivateKey: idpData.encPrivateKey,
        messageSigningOrder: idpData.messageSigningOrder,
        loginResponseTemplate: this.loginResponseTemplate,
      });
      const info = { extract: { request: { id: requestId } } };
      const user: User = {
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        userId: req.body.userId,
      } as User;

      this.logger.log('Creating Login Response for Service Provider');
      const result = await idp.createLoginResponse(
        sp,
        info,
        'post',
        user,
        this.createTemplateCallback(idp, sp, 'post', user, requestId),

        idpData.messageSigningOrder ===
          MessageSigningOrderEnum.ENCRYPT_THEN_SIGN
          ? true
          : false,
        session.relayState || idpData.defaultRelayState || '',
      );

      savedSession.user = user;
      await savedSession.save();

      this.logger.log('Login Resonse created ,redirecting to SP');
      return res.render('sp-post', result);
    } catch (error) {
      this.logger.error('Error in creating session', error);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }

  async loginRedirect(req: any, res: any, idpId: string) {
    // if (req.session) {
    //   const SAMLRequest = req.query.SAMLRequest;

    //   const decodedString = Buffer.from(SAMLRequest, 'base64').toString(
    //     'ascii',
    //   );
    //   const { issuer } = samlify.Extractor.extract(decodedString, [
    //     {
    //       key: 'issuer',
    //       localPath: ['AuthnRequest', 'Issuer'],
    //       attributes: [],
    //     },
    //   ]);
    //   this.logger.log('SAML Request From EntittyId', issuer);

    //   if (req.session.spEntityId === issuer && req.session?.user !== {}) {
    //     const { user, idpId } = req.session;
    //     const spMetaData = await this.serviceProviderService.getMetaData(idpId);
    //     const sp = samlify.ServiceProvider({
    //       metadata: spMetaData,
    //     });

    //     const idpMetaData = await this.getMetaData(idpId);
    //     const idp = samlify.IdentityProvider({
    //       metadata: idpMetaData,
    //     });
    //     const { extract } = await idp.parseLoginRequest(sp, 'redirect', req);
    //     //  const info = { extract: { request: { id: requestId } } };
    //     const result = await idp.createLoginResponse(
    //       sp,
    //       extract,
    //       'post',
    //       user,
    //       this.createTemplateCallback(
    //         idp,
    //         sp,
    //         'post',
    //         user,
    //         extract.request.id,
    //       ),
    //     );
    //     return res.render('sp-post', result);
    //   }
    // } else {
    req.octetString = this.buildOctetStringFromQuery(req.query);
    return this.loginPost(req, res, 'redirect', idpId);
    //}

    //
  }

  async logoutPost(req: any, res: any, binding: string, idpId: string) {
    try {
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
      this.logger.log(
        `Logout Request Received, Binding: ${binding}, ${decodedString} ${relayState} ${SAMLRequest}`,
      );

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

      this.logger.log(`SAML Request From EntittyId : ${issuer}`);

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

      this.logger.log(
        'Logout Request Parsed, Creating Logout Response',
        extract,
      );
      const result = idp.createLogoutResponse(sp, extract, binding, relayState);
      this.logger.log(
        `Response Created, Redirecting to SP json: ${JSON.stringify(result)}`,
      );

      return res.render('sp-post', result);
    } catch (error) {
      this.logger.error(error);
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
    (_idp: any, _sp: any, _binding: string, user: any, id: string) =>
    (template) => {
      const now = new Date();
      const spEntityID = _sp.entityMeta.getEntityID();
      const idpSetting = _idp.entitySetting;
      const fiveMinutesLater = new Date(now.getTime());
      fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
      const sessionIndex = `_${uuid.v4()}`;
      const tvalue = {
        ID: id,
        AssertionID: idpSetting.generateID
          ? idpSetting.generateID()
          : `${uuid.v4()}`,
        Destination: _sp.entityMeta.getAssertionConsumerService(_binding),
        Audience: spEntityID,
        SubjectRecipient: _sp.entityMeta.getAssertionConsumerService(_binding),
        NameIDFormat: _idp.entitySetting.nameIDFormat,
        NameID: user.email,
        Issuer: _idp.entityMeta.getEntityID(),
        IssueInstant: now.toISOString(),
        ConditionsNotBefore: now.toISOString(),
        ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
        SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
        AssertionConsumerServiceURL:
          _sp.entityMeta.getAssertionConsumerService(_binding),
        EntityID: spEntityID,
        InResponseTo: id,
        StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
        attrUserEmail: user.email,
        attrUserId: user.userId,
        attrUserFirstName: user.firstName,
        attrUserLastName: user.firstName,
        AuthnStatement: `
                <saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionNotOnOrAfter="${fiveMinutesLater.toISOString()}" SessionIndex="${sessionIndex}">
                    <saml:AuthnContext>
                        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
                    </saml:AuthnContext>
                </saml:AuthnStatement>
                `,
      };
      return {
        id: id,
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
      return {
        message: 'Idp Deleted Successfully',
      };
    } catch (error) {
      this.logger.error(error);
      throw new HttpException(
        error.message,
        error.status || HttpStatus.BAD_GATEWAY,
      );
    }
  }
}
