import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types/tokens.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.register(authDto);
  }

  @Post('login')
  login(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.login(authDto);
  }

  @Post('logout')
  logout() {
    return this.authService.logout();
  }

  @Post('refresh')
  refresh() {
    return this.authService.refresh();
  }
}
