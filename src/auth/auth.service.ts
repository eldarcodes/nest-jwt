import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

  async register(authDto: AuthDto) {
    // const newUser = await this.prismaService.user.create({
    //   data: {
    //     email: authDto.email,
    //   },
    // });
  }

  async login() {
    return null;
  }

  async logout() {
    return null;
  }

  async refresh() {
    return null;
  }
}
