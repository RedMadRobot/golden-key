//
//  Shared.swift
//  GoldenKey
//
//  Created by Alexander Ignatev on 11/06/2019.
//  Copyright © 2019 RedMadRobot. All rights reserved.
//

import Foundation

internal protocol Deallocatable {
    func deallocate()
}

extension UnsafeMutablePointer: Deallocatable {}
extension UnsafeRawBufferPointer: Deallocatable {}

internal final class Shared<Pointer> where Pointer: Deallocatable {
    let pointer: Pointer

    init(_ pointer: Pointer) {
        self.pointer = pointer
    }

    deinit {
        pointer.deallocate()
    }
}
