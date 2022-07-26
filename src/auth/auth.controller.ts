import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import RequestWithUser from './interfaces/requestWithUser.interface';
import { Tokens } from './types/tokens.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.register(authDto);
  }

  @Post('login')
  login(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.login(authDto);
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  logout(@Req() req: RequestWithUser) {
    const user = req.user;

    return this.authService.logout(user.id);
  }

  @Post('refresh')
  @UseGuards(AuthGuard('jwt-refresh'))
  refresh() {
    return this.authService.refresh();
  }
}
