// Project-owned fixture: only this test executable is run by the validator.
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

struct EXPoint { double x; double y; };

@protocol EXZetaProtocol <NSObject>
- (long long)count;
@end

@protocol EXReadable <EXZetaProtocol>
- (NSString *)title;
@optional
+ (BOOL)isAvailable;
@end

@interface EXZetaBase : NSObject <EXZetaProtocol>
@property(nonatomic, copy, getter=displayName, setter=updateDisplayName:) NSString *name;
- (long long)count;
@end

@implementation EXZetaBase
- (long long)count { return 7; }
@end

@interface EXChild : EXZetaBase <EXReadable> {
    struct EXPoint _origin;
    int _samples[3];
}
@property(nonatomic, strong) id<EXReadable> delegate;
@property(class, nonatomic, readonly) NSUInteger capacity;
- (NSString *)title;
- (struct EXPoint)translatePoint:(struct EXPoint)point;
- (void)fillNumbers:(int (*)[3])values;
- (void)consumeBlock:(void (^)(int))block;
- (SEL)operation;
+ (Class)relatedClass;
+ (BOOL)isAvailable;
@end

@implementation EXChild
+ (NSUInteger)capacity { return 3; }
- (NSString *)title { return @"fixture"; }
- (struct EXPoint)translatePoint:(struct EXPoint)point { return point; }
- (void)fillNumbers:(int (*)[3])values { (*values)[0] = 1; }
- (void)consumeBlock:(void (^)(int))block { (void)block; }
- (SEL)operation { return @selector(title); }
+ (Class)relatedClass { return self; }
+ (BOOL)isAvailable { return YES; }
@end

@interface EXChild (Extras)
@property(nonatomic, readonly) double fraction;
- (int)extraValue;
@end

@implementation EXChild (Extras)
- (double)fraction { return 0.5; }
- (int)extraValue { return 11; }
@end

static NSString *Text(const char *value) {
    return value ? @(value) : @"";
}

static NSDictionary *MethodRecord(SEL selector, const char *types, BOOL isClass,
                                   BOOL optional) {
    return @{ @"name": NSStringFromSelector(selector), @"types": Text(types),
              @"is_class": @(isClass), @"optional": @(optional) };
}

static NSArray *Methods(Class cls, BOOL isClass, NSSet *skip) {
    NSMutableArray *result = [NSMutableArray array];
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    for (unsigned i = 0; i < count; ++i) {
        SEL name = method_getName(methods[i]);
        if (![skip containsObject:NSStringFromSelector(name)])
            [result addObject:MethodRecord(name, method_getTypeEncoding(methods[i]),
                                          isClass, NO)];
    }
    free(methods);
    return result;
}

static NSArray *Properties(Class cls, BOOL isClass, NSSet *skip) {
    NSMutableArray *result = [NSMutableArray array];
    unsigned count = 0;
    objc_property_t *properties = class_copyPropertyList(cls, &count);
    for (unsigned i = 0; i < count; ++i) {
        NSString *name = Text(property_getName(properties[i]));
        if (![skip containsObject:name])
            [result addObject:@{ @"name": name,
                                 @"attributes": Text(property_getAttributes(properties[i])),
                                 @"is_class": @(isClass) }];
    }
    free(properties);
    return result;
}

static NSArray *Adoptions(Protocol * __unsafe_unretained *protocols, unsigned count) {
    NSMutableArray *result = [NSMutableArray array];
    for (unsigned i = 0; i < count; ++i)
        [result addObject:Text(protocol_getName(protocols[i]))];
    free(protocols);
    return result;
}

static NSDictionary *ClassRecord(Class cls) {
    NSSet *skipMethods = [NSSet setWithObjects:@"fraction", @"extraValue", nil];
    NSSet *skipProperties = [NSSet setWithObject:@"fraction"];
    NSMutableArray *methods = [Methods(cls, NO, skipMethods) mutableCopy];
    [methods addObjectsFromArray:Methods(object_getClass(cls), YES, nil)];
    NSMutableArray *properties = [Properties(cls, NO, skipProperties) mutableCopy];
    [properties addObjectsFromArray:Properties(object_getClass(cls), YES, nil)];
    NSMutableArray *ivars = [NSMutableArray array];
    unsigned count = 0;
    Ivar *list = class_copyIvarList(cls, &count);
    for (unsigned i = 0; i < count; ++i)
        [ivars addObject:@{ @"name": Text(ivar_getName(list[i])),
                            @"types": Text(ivar_getTypeEncoding(list[i])),
                            @"offset": @(ivar_getOffset(list[i])) }];
    free(list);
    Protocol * __unsafe_unretained *protocols = class_copyProtocolList(cls, &count);
    return @{ @"name": Text(class_getName(cls)),
              @"superclass": Text(class_getName(class_getSuperclass(cls))),
              @"methods": methods, @"properties": properties, @"ivars": ivars,
              @"protocols": Adoptions(protocols, count) };
}

static NSDictionary *ProtocolRecord(Protocol *proto) {
    NSMutableArray *methods = [NSMutableArray array];
    for (unsigned required = 0; required < 2; ++required) {
        for (unsigned instance = 0; instance < 2; ++instance) {
            unsigned count = 0;
            struct objc_method_description *list = protocol_copyMethodDescriptionList(
                proto, required, instance, &count);
            for (unsigned i = 0; i < count; ++i)
                [methods addObject:MethodRecord(list[i].name, list[i].types,
                                               !instance, !required)];
            free(list);
        }
    }
    unsigned count = 0;
    Protocol * __unsafe_unretained *protocols = protocol_copyProtocolList(proto, &count);
    return @{ @"name": Text(protocol_getName(proto)), @"methods": methods,
              @"properties": @[], @"protocols": Adoptions(protocols, count) };
}

int main(void) {
    @autoreleasepool {
        NSMutableArray *methods = [NSMutableArray array];
        for (NSString *name in @[@"fraction", @"extraValue"]) {
            Method method = class_getInstanceMethod(EXChild.class, NSSelectorFromString(name));
            [methods addObject:MethodRecord(method_getName(method),
                                           method_getTypeEncoding(method), NO, NO)];
        }
        objc_property_t property = class_getProperty(EXChild.class, "fraction");
        NSDictionary *category = @{ @"name": @"Extras", @"class_name": @"EXChild",
            @"protocols": @[], @"methods": methods,
            @"properties": @[@{ @"name": @"fraction", @"is_class": @NO,
                                  @"attributes": Text(property_getAttributes(property)) }] };
        // Reverse inheritance/adoption order so the exporter must order dependencies.
        NSDictionary *data = @{ @"classes": @[ClassRecord(EXChild.class), ClassRecord(EXZetaBase.class)],
            @"protocols": @[ProtocolRecord(@protocol(EXReadable)), ProtocolRecord(@protocol(EXZetaProtocol))],
            @"categories": @[category] };
        NSData *encoded = [NSJSONSerialization dataWithJSONObject:data
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
        fwrite(encoded.bytes, 1, encoded.length, stdout);
        fputc('\n', stdout);
    }
    return 0;
}
