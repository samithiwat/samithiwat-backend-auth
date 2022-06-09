import { Injectable } from '@nestjs/common';
import { JwtService as Jwt } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { TokenPayload } from 'src/common/types/auth';
import { Repository } from 'typeorm';
import { Auth } from '../entities/auth.entity';

@Injectable()
export class JwtService {
  constructor(
    @InjectRepository(Auth) private authRepository: Repository<Auth>,
    private readonly jwtService: Jwt,
  ) {}

  async decode(token: string): Promise<TokenPayload> {
    return this.jwtService.decode(token) as TokenPayload;
  }

  async validate(accessToken: string): Promise<Auth> {
    return this.authRepository
      .createQueryBuilder('auth')
      .leftJoinAndSelect('auth.tokens', 'token')
      .where('token.accessToken = :accessToken', { accessToken })
      .getOne();
  }

  async generate(auth: Auth): Promise<string> {
    return this.jwtService.sign({ id: auth.id });
  }
}
