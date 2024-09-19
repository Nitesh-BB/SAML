import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Put,
  Req,
  Res,
} from '@nestjs/common';
import { ApiExcludeEndpoint, ApiTags } from '@nestjs/swagger';
import { CreateIdpDto } from './dto/create-idp.dto';
import { UpdateIdpDto } from './dto/update-idp.dto';
import { IdpService } from './idp.service';

@Controller('idp')
@ApiTags('identity-provider')
export class IdpController {
  constructor(private readonly idpService: IdpService) {}

  @Post('create')
  async createIdp(@Body() createIdpDto: CreateIdpDto) {
    return this.idpService.createIdp(createIdpDto);
  }

  @Get('metadata/:idpId')
  async getMetaData(@Res() res: any, @Param('idpId') idpId: string) {
    const metadata = await this.idpService.getMetaData(idpId);
    res.setHeader('Content-Type', 'text/xml');
    return res.send(metadata);
  }

  @Get('get/:idpId')
  async getIdp(@Param('idpId') idpId: string) {
    return this.idpService.getIdp(idpId);
  }
  @ApiExcludeEndpoint()
  @Post('login/post')
  async loginPostRequest(@Res() res: any, @Req() req: any) {
    return this.idpService.createSession(req, res);
  }

  @ApiExcludeEndpoint()
  @Get('login/:idpId')
  async login(@Res() res: any, @Req() req: any, @Param('idpId') idpId: string) {
    return this.idpService.loginRedirect(req, res, idpId);
  }

  @ApiExcludeEndpoint()
  @Post('login/:idpId')
  async loginPost(
    @Res() res: any,
    @Req() req: any,
    @Param('idpId') idpId: string,
  ) {
    return this.idpService.loginPost(req, res, 'post', idpId);
  }

  @ApiExcludeEndpoint()
  @Post('logout/:idpId')
  async logoutPost(
    @Res() res: any,
    @Req() req: any,
    @Param('idpId') idpId: string,
  ) {
    return this.idpService.logoutPost(req, res, 'post', idpId);
  }

  @ApiExcludeEndpoint()
  @Get('logout/:idpId')
  async logoutRedirect(
    @Res() res: any,
    @Req() req: any,
    @Param('idpId') idpId: string,
  ) {
    return this.idpService.logoutRedirect(req, res, idpId);
  }

  @Patch('/update/:idpId')
  async updateIdp(@Body() body: UpdateIdpDto, @Param('idpId') idpId: string) {
    return this.idpService.updateIdp(idpId, body);
  }

  @Delete('/:idpId')
  async deleteIdp(@Param('idpId') idpId: string) {
    return this.idpService.deleteIdp(idpId);
  }
}
