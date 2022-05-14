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

  async findFromPayload(decode: TokenPayload): Promise<Auth> {
    return this.authRepository.findOne({ userId: decode.id });
  }

  async generate(auth: Auth): Promise<string> {
    return this.jwtService.sign({ id: auth.id });
  }

  async verify(token: string): Promise<TokenPayload> {
    return this.jwtService.verify(token);
  }
}
