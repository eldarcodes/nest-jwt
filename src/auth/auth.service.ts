import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types/tokens.interface';
import PrismaErrors from 'src/prisma/enum/prismaErrors.enum';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(authDto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashData(authDto.password);

    try {
      const newUser = await this.prismaService.user.create({
        data: {
          email: authDto.email,
          hash: hashedPassword,
        },
      });

      const tokens = await this.getTokens(newUser.id, newUser.email);
      await this.updateRefreshTokenHash(newUser.id, tokens.refresh_token);

      return tokens;
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
  }

  async login(authDto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: { email: authDto.email },
    });

    if (!user) {
      throw new ForbiddenException('Access denied');
    }

    const passwordMatch = await bcrypt.compare(authDto.password, user.hash);

    if (!passwordMatch) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refresh() {
    return null;
  }

  hashData(data: string) {
    const saltOrRounds = 10;

    return bcrypt.hash(data, saltOrRounds);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
          expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
        },
      ),
      await this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: this.configService.get('JWT_REFRESH_TOKEN_SECRET'),
          expiresIn: this.configService.get(
            'JWT_REFRESH_TOKEN_EXPIRATION_TIME',
          ),
        },
      ),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async updateRefreshTokenHash(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);

    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
}
