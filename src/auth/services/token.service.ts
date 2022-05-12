import { HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateTokenDto } from '../dto/create-token.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';
import { Token } from '../entities/token.entity';
import { TokenResponse } from '../interface/token.interface';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class TokenService {
  constructor(
    @InjectRepository(Token) private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  async create(createTokenDto: CreateTokenDto): Promise<TokenResponse> {
    const res = new ResponseDto({
      statusCode: HttpStatus.CREATED,
      errors: null,
      data: null,
    }) as TokenResponse;

    createTokenDto.accessToken = createTokenDto.accessToken
      ? createTokenDto.accessToken
      : await this.jwtService.generate(createTokenDto.auth);

    createTokenDto.refreshToken = createTokenDto.refreshToken
      ? createTokenDto.refreshToken
      : await this.refreshTokenService.generate();

    try {
      const token = await this.tokenRepository.save(createTokenDto);
      res.data = token;
      return res;
    } catch (err) {
      res.statusCode = HttpStatus.UNPROCESSABLE_ENTITY;
      res.errors = ['Refresh token already exists'];
      return res;
    }
  }

  async findOne(id: number): Promise<TokenResponse> {
    const token = await this.tokenRepository.findOne(id);

    return new ResponseDto({
      statusCode: token ? HttpStatus.OK : HttpStatus.NOT_FOUND,
      errors: token ? null : ['Not found token'],
      data: token ? token : null,
    }) as TokenResponse;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
