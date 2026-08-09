#ifndef ATTRIBUTES_H
#define ATTRIBUTES_H

#define AttrConst __attribute__ ((const))
#define AttrPure __attribute__ ((pure))
#define AttrNoReturn __attribute__ ((noreturn))
#define AttrNoInline __attribute__ ((noinline))
#define AttrPrintf(sidx, vidx) __attribute__ ((format (printf, sidx, vidx)))
#define AttrPacked __attribute__ ((packed))
#define AttrMalloc __attribute__ ((malloc))
#define AttrDtor __attribute__ ((destructor))

#endif
