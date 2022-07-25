import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types/tokens.interface';
import PrismaErrors from 'src/prisma/enum/prismaErrors.enum';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}

  hashData(data: string) {
    const saltOrRounds = 10;

    return bcrypt.hash(data, saltOrRounds);
  }

  async register(authDto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashData(authDto.password);

    try {
      const newUser = await this.prismaService.user.create({
        data: {
          email: authDto.email,
          hash: hashedPassword,
        },
      });
    } catch (error) {
      if (error?.code === PrismaErrors.UniqueViolation) {
        throw new HttpException(
          'User with that email already exists',
          HttpStatus.BAD_REQUEST,
        );
      }

      throw new HttpException(
        'Something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    return { access_token: '', refresh_token: '' };
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
