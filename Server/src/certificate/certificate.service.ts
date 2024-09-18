import { HttpException, Injectable, Logger } from '@nestjs/common';
import * as rs from 'jsrsasign';
import { GenerateCertficateDto } from './dto/generate-certficate.dto';
import * as selfsigned from 'selfsigned';
import { v4 as uuid } from 'uuid';
import { extname } from 'path';
@Injectable()
export class CertificateService {
  private readonly logger = new Logger('CertificateService');

  // onModuleInit() {
  //   const cert = this.generateCertificate({
  //     countryName: 'IN',
  //     state: 'Maharashtra',
  //     locality: 'Pune',
  //     organization: 'blue-bricks',
  //     organizationUnit: 'SAML-SSO',
  //     commonName: 'https://www.blue-bricks.com',
  //     sigalg: 'SHA256withRSA',
  //     validDays: 365,
  //     emailAddress: 'nitesh@mollatech.com',
  //   });

  //   console.log(cert.certificate);
  // }

  generateCertificate(generateCertficateDto?: GenerateCertficateDto): {
    certificate: string;
    privateKey: string;
    publicKey: string;
  } {
    const kp = rs.KEYUTIL.generateKeypair('RSA', 2048);
    const prv = kp.prvKeyObj;
    const pub = kp.pubKeyObj;
    const prvpem = rs.KEYUTIL.getPEM(prv, 'PKCS8PRV');
    const pubpem = rs.KEYUTIL.getPEM(pub, 'PKCS8PUB');
    const validTillDate = new Date(
      new Date().getTime() +
        1000 * 60 * 60 * 24 * (generateCertficateDto.validDays || 365),
    );
    let validTill =
      validTillDate.toISOString().split('T')[0].split('-').join('') +
      validTillDate.toISOString().split('T')[1].split(':').join('');

    validTill = validTill.split('.')[0] + 'Z';

    // STEP2. specify certificate parameters
    const x = new rs.KJUR.asn1.x509.Certificate({
      serial: { int: uuid() },
      issuer: {
        C: 'IN',
        ST: 'Maharashtra',
        L: 'Pune',
        O: 'blue-bricks',
        OU: 'SAML-SSO',
        CN: 'https://www.blue-bricks.com',
      },

      subject: {
        C: generateCertficateDto.countryName,
        ST: generateCertficateDto.state,
        L: generateCertficateDto.locality,
        O: generateCertficateDto.organization,
        OU: generateCertficateDto.organizationUnit,
        CN: generateCertficateDto.commonName,
      },
      notbefore: Date.now(),
      notafter: validTill,
      sbjpubkey: pub, // can specify public key object or PEM string
      sigalg: generateCertficateDto.sigalg || 'SHA512withRSA',
      cakey: prv, // can specify private key object or PEM string

      ext: [
        // add subjectKeyIdentifier and authorityKeyIdentifier extension
        {
          extname: 'basicConstraints',
          critical: true, // This field is optional; set as needed
          cA: true,
        },
        {
          extname: 'subjectKeyIdentifier', // Subject Key Identifier
          kid: { hex: rs.KJUR.crypto.Util.hashHex(pubpem, 'sha1') }, // Generate SKI using SHA-1 hash of the public key PEM
        },
        {
          extname: 'authorityKeyIdentifier', // Authority Key Identifier
          kid: { hex: rs.KJUR.crypto.Util.hashHex(pubpem, 'sha1') }, // Can be the same as SKI or different if using a different CA
        },
      ],
    });

    return {
      privateKey: prvpem.replace(/\r\n/g, '\n'),
      publicKey: pubpem,
      certificate: x.getPEM().replace(/\r\n/g, '\n'),
    };
  }

  generateSelfSignedCertificate(generateCertficateDto?: GenerateCertficateDto) {
    try {
      this.logger.log('Generating self signed certificate');
      /// const attrs = [{ name: 'commonName', value: 'contoso.com' }];
      const attrs = [
        {
          value: generateCertficateDto.commonName,
          type: 'server',
          name: 'blue-bricks',
        },
      ];
      const pems = selfsigned.generate(attrs, { days: 365 });
      return {
        privateKey: pems.private,
        publicKey: pems.public,
        certificate: pems.cert,
      };
    } catch (error) {
      this.logger.error(
        `Error while generating self signed certificate: ${error}`,
      );
      throw new HttpException(error.message, error.status || 500);
    }
  }
}
