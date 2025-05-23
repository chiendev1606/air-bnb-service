import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { LoginResponseDto } from './login-response.dto';
import { ApiOperationDecorator } from '@air-bnb/decorators';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  @ApiOperationDecorator({
    summary: 'Login',
    description: 'Login to the system',
    operationId: 'login',
    type: LoginResponseDto,
  })
  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return new LoginResponseDto(this.jwtService.sign(payload));
  }
}
