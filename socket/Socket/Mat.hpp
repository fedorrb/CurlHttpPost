
double  FP(FD*);
double  round(double*, int);
double  trunc(double*, int);
void    Cpy2(FD*, double*);


inline void Cpy2(FD *Dst, long Src)
{
  Ldl(Src, FieldLn(Dst));
  Std(Dst);
}
inline void Cpy2(FD *Dst, FD *Src)
{
  Ldd(Src);
  Std(Dst);
}
inline int   Cmp2(FD *Dst, FD *Src)
{
  Ldd(Dst);
  Ldd(Src);
  return Cmp();
}
inline int   Cmp2(FD *Dst, char *Str)
{
  Ldd(Dst);
  Ldv(Str);
  return Cmp();
}
inline int   Cmp2(FD *Dst, int V)
{
  Ldd(Dst);
  Ldi(V,FieldLn(Dst));
  return Cmp();
}
inline int   Cmp2(FD *Dst, long V)
{
  Ldd(Dst);
  Ldl(V,FieldLn(Dst));
  return Cmp();
}
