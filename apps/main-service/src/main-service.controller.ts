import { Public } from '@air-bnb/decorators';
import { Identify } from '@air-bnb/decorators/identify.decorator';
import { Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { MainServicesService } from './main-service.service';
import { AuthService } from './modules/auth/auth.service';
import { JwtAuthGuard } from './modules/auth/jwt-auth.guard';
import { LocalAuthGuard } from './modules/auth/local-auth.guard';

@Controller()
export class MainServiceController {
  constructor(
    private readonly mainServicesService: MainServicesService,
    private readonly authService: AuthService,
  ) {}

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('auth/login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(LocalAuthGuard)
  @Post('auth/logout')
  async logout(@Request() req) {
    return req.logout();
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req, @Identify() user) {
    console.log(user);

    return req.user;
  }
}
